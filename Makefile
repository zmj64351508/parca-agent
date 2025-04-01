.PHONY: all crossbuild build build-debug snap

all: crossbuild

GIT_COMMIT_ID := $(shell git rev-parse HEAD)
GIT_COMMIT_DATE := $(shell git show -s --format=%cd --date=iso-strict HEAD)
build-android:
	CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ GOOS=linux GOARCH=arm64 go build -o parca-agent -buildvcs=false -ldflags="-extldflags=-static -X main.commit=${GIT_COMMIT_ID} -X main.date=${GIT_COMMIT_DATE} -X main.goArch=arm64" -tags osusergo,netgo,debugtracer

crossbuild:
	DOCKER_CLI_EXPERIMENTAL="enabled" docker run \
		--rm \
		--privileged \
		-v "/var/run/docker.sock:/var/run/docker.sock" \
		-v "$(shell pwd):/__w/parca-agent/parca-agent" \
		-v "$(GOPATH)/pkg/mod":/go/pkg/mod \
		-w "/__w/parca-agent/parca-agent" \
		ghcr.io/goreleaser/goreleaser-cross:v1.22.4 \
		release --snapshot --clean --skip=publish --verbose

build:
	go build -o parca-agent -buildvcs=false -ldflags="-extldflags=-static" -tags osusergo,netgo,debugtracer

build-debug:
	go build -o parca-agent-debug -buildvcs=false -ldflags="-extldflags=-static" -tags osusergo,netgo,debugtracer -gcflags "all=-N -l"

snap: crossbuild
	cp ./dist/metadata.json snap/local/metadata.json

	cp ./dist/linux-amd64_linux_amd64_v1/parca-agent snap/local/parca-agent
	snapcraft pack --verbose --build-for amd64

	cp ./dist/linux-arm64_linux_arm64/parca-agent snap/local/parca-agent
	snapcraft pack --verbose --build-for arm64
