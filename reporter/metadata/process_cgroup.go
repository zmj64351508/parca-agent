package metadata

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	lru "github.com/elastic/go-freelru"
	"github.com/prometheus/prometheus/model/labels"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

type processCgroupMetadataProvider struct {
	cgroupRootToName map[int]string
	cgroupIDToPath   map[int]map[uint64]string
	cgroupCache      *lru.SyncedLRU[libpf.PID, []cgroup]
}

func scanProcCgroups() (map[int]string, error) {
	cgroupRootToName := make(map[int]string)

	data, err := readFileNoStat("/proc/cgroups")
	if err != nil {
		return nil, fmt.Errorf("Failed to read /proc/cgroups: %v", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineno := 0
	subsysNameIndex := -1
	hierarchyIndex := -1
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, "\t")
		if lineno == 0 {
			for i, field := range fields {
				if field == "#subsys_name" {
					subsysNameIndex = i
				} else if field == "hierarchy" {
					hierarchyIndex = i
				}
			}
			if hierarchyIndex == -1 || subsysNameIndex == -1 {
				return nil, fmt.Errorf("Failed to find hierarchy/subsys_name in /proc/cgroups")
			}
		} else {
			root, err := strconv.Atoi(fields[hierarchyIndex])
			if err != nil {
				return nil, fmt.Errorf("Failed to parse hierarchy(%s) in /proc/cgroups: %v", fields[hierarchyIndex], err)
			}
			name := fields[subsysNameIndex]
			if len(strings.Split(name, ",")) > 1 {
				// TODO: Cgroup with multiple subsys is not supported
				continue
			}
			if root != 0 {
				cgroupRootToName[root] = name
			}
		}
		lineno++
	}
	cgroupRootToName[0] = "cgroup2"

	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("Failed to read /proc/cgroups: %v", err)
	}

	return cgroupRootToName, nil
}

func findCgroupMountPoint(cgroupRootToName map[int]string) (map[int]string, error) {
	cgroupRootToMountPoint := make(map[int]string)
	data, err := readFileNoStat("/proc/mounts")
	if err != nil {
		return nil, fmt.Errorf("Failed to read /proc/mounts: %v", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, " ")
		if len(fields) < 5 {
			continue
		}
		if fields[2] == "cgroup" {
			options := strings.Split(fields[3], ",")
			for cgroupRoot, cgroupName := range cgroupRootToName {
				for _, option := range options {
					if option == cgroupName {
						if _, exists := cgroupRootToMountPoint[cgroupRoot]; !exists {
							cgroupRootToMountPoint[cgroupRoot] = fields[1]
						}
					}
				}
			}
		} else if fields[2] == "cgroup2" {
			if _, exists := cgroupRootToMountPoint[0]; !exists {
				cgroupRootToMountPoint[0] = fields[1]
			}
		}
	}
	if len(cgroupRootToMountPoint) != len(cgroupRootToName) {
		return nil, fmt.Errorf("Failed to find all cgroup mount points")
	}
	return cgroupRootToMountPoint, nil
}

func scanCgroupIDs(mountPoint string) (map[uint64]string, error) {
	cgroupIDToPath := make(map[uint64]string)
	err := filepath.WalkDir(mountPoint, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("Failed to walk cgroup: %v", err)
		}
		if d.IsDir() {
			dinfo, err := d.Info()
			if err != nil {
				return fmt.Errorf("Failed to get cgroup dir info: %s, %v", path, err)
			}
			stat, ok := dinfo.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("Failed to get cgroup dir stat: %s", path)
			}
			relpath, err := filepath.Rel(mountPoint, path)
			if err != nil {
				return fmt.Errorf("Failed to get cgroup rel path: %s, %v", path, err)
			}
			if relpath == "." {
				relpath = ""
			}
			cgroupIDToPath[stat.Ino] = "/" + relpath
			return nil
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to scan cgroup %s: %v", mountPoint, err)
	}
	return cgroupIDToPath, nil
}

func NewProcessCgroupMetadataProvider() DynamicMetadataProvider {
	cgroupRootToName, err := scanProcCgroups()
	if err != nil {
		log.Errorf("Failed to scan /proc/cgroups: %v", err)
		return nil
	}

	cgroupRootToMountPoint, err := findCgroupMountPoint(cgroupRootToName)

	cgroupIDToPath := make(map[int]map[uint64]string, 0)
	for i, mountPoint := range cgroupRootToMountPoint {
		cgroupIDToPath[i], err = scanCgroupIDs(mountPoint)
		if err != nil {
			log.Errorf("%v", err)
			return nil
		}
		for cgroupID, path := range cgroupIDToPath[i] {
			log.Debugf("cgroupRoot %d, cgroupID %d, path %s", i, cgroupID, path)
		}
	}

	cache, err := lru.NewSynced[libpf.PID, []cgroup](4096, libpf.PID.Hash32)
	if err != nil {
		log.Errorf("Failed to create cgroup cache %v", err)
		return nil
	}
	return &processCgroupMetadataProvider{
		cgroupRootToName: cgroupRootToName,
		cgroupIDToPath:   cgroupIDToPath,
		cgroupCache:      cache,
	}
}

func (p process) cgroups() ([]cgroup, error) {
	data, err := readFileNoStat(p.path("cgroup"))
	if err != nil {
		return []cgroup{}, err
	}
	cgroups, err := parseCgroups(data)
	if err != nil {
		return []cgroup{}, err
	}
	return cgroups, nil
}

func (cmp *processCgroupMetadataProvider) AddMetadata(meta *samples.TraceEventMeta, lb *labels.Builder) bool {
	for cgroupRoot, cgroupID := range meta.CgroupIDs {
		if cgroupID > 0 {
			name, exist := cmp.cgroupRootToName[cgroupRoot]
			if !exist {
				log.Debugf("cgroupRoot %d not found in cgroupRootToName", cgroupRoot)
				return false
			}
			path, exist := cmp.cgroupIDToPath[cgroupRoot][cgroupID]
			lb.Set("__meta_process_cgroup_"+name, path)
		} else {
			// Cgroup has not been known by the ebpf tracer, use /proc/pid/cgroup to get it
			var cgroups []cgroup
			if cached, exist := cmp.cgroupCache.Get(meta.PID); exist {
				cgroups = cached
			} else {
				// slow path
				var err error
				p := process(meta.PID)
				cgroups, err = p.cgroups()
				if err != nil {
					log.Debugf("Failed to get cgroup info for pid %d: %v", meta.PID, err)
					return false
				}
				cmp.cgroupCache.Add(meta.PID, cgroups)
			}
			for _, cgroup := range cgroups {
				// TODO: Cgroup with multiple subsys is not supported
				if cgroup.hierarchyID == cgroupRoot && len(cgroup.controllers) == 1 {
					lb.Set("__meta_process_cgroup_"+cgroup.controllers[0], cgroup.path)
				}
			}
		}
	}
	return true
}
