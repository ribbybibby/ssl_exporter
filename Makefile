GOPATH      := $(shell go env GOPATH)

BIN_DIR             ?= $(shell pwd)/bin
BIN_NAME            ?= ssl_exporter$(shell go env GOEXE)
DOCKER_IMAGE_NAME   ?= ssl-exporter
DOCKER_IMAGE_TAG    ?= $(subst /,-,$(shell git rev-parse --abbrev-ref HEAD))

# Race detector is only supported on amd64.
RACE := $(shell test $$(go env GOARCH) != "amd64" || (echo "-race"))

export APP_HOST        ?= $(shell hostname)
export APP_BRANCH      ?= $(shell git describe --all --contains --dirty HEAD)
export APP_VERSION     := $(shell cat VERSION)
export APP_REVISION    := $(shell git rev-parse HEAD)
export APP_USER        := $(shell id -u --name)
export APP_BUILD_DATE  := $(shell date '+%Y%m%d-%H:%M:%S')

all: clean format vet build test

style:
	@echo ">> checking code style"
	@! gofmt -s -d $(shell find . -path ./vendor -prune -o -name '*.go' -print) | grep '^'

test:
	@echo ">> running tests"
	go test -short -v $(RACE) ./...

format:
	@echo ">> formatting code"
	@go fmt ./...

vet:
	@echo ">> vetting code"
	@go vet $(pkgs)

build:
	@echo ">> building binary"
	@CGO_ENABLED=0 go build -v \
		-ldflags "-X github.com/prometheus/common/version.Version=$(APP_VERSION) \
		-X github.com/prometheus/common/version.Revision=$(APP_REVISION) \
		-X github.com/prometheus/common/version.Branch=$(APP_BRANCH) \
		-X github.com/prometheus/common/version.BuildUser=$(APP_USER)@$(APP_HOST) \
		-X github.com/prometheus/common/version.BuildDate=$(APP_BUILD_DATE)\
		" \
		-o $(BIN_NAME) .

docker:
	@echo ">> building docker image"
	@docker build -t "$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)" .

$(GOPATH)/bin/goreleaser:
	@curl -sfL https://install.goreleaser.com/github.com/goreleaser/goreleaser.sh | BINDIR=$(GOPATH)/bin sh

snapshot: $(GOPATH)/bin/goreleaser
	@echo ">> building snapshot"
	@$(GOPATH)/bin/goreleaser --snapshot --skip-sign --skip-validate --skip-publish --rm-dist

release: $(GOPATH)/bin/goreleaser
	@$(GOPATH)/bin/goreleaser release

clean:
	@echo ">> removing build artifacts"
	@rm -Rf $(BIN_DIR)
	@rm -Rf $(BIN_NAME)

.PHONY: all style test format vet build docker snapshot release clean