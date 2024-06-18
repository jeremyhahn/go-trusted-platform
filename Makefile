ORG                     := automatethethingsllc
TARGET_OS               := linux
TARGET_ARCH             := $(shell uname -m)

ARCH                    := $(shell go env GOARCH)
OS                      := $(shell go env GOOS)
LONG_BITS               := $(shell getconf LONG_BIT)

GOBIN                   := $(shell dirname `which go`)

ARM_CC                  ?= arm-linux-gnueabihf-gcc-8
ARM_CC_64				?= aarch64-linux-gnu-gcc

REPO                    ?= github.com
PACKAGE                 ?= go-trusted-platform
APPNAME                 ?= trusted-platform

APP_VERSION       		?= $(shell git describe --tags --abbrev=0)
GIT_TAG                 = $(shell git describe --tags)
GIT_HASH                = $(shell git rev-parse HEAD)
GIT_BRANCH              = $(shell git branch --show-current)	
BUILD_DATE              = $(shell date '+%Y-%m-%d_%H:%M:%S')

CLONE_HOST              ?= github.com
CLONE_OWNER             ?= jeremyhahn
CLONE_APP_NAME          ?= new-app
CLONE_PACKAGE           ?= go-$(CLONE_APP_NAME)
CLONE_DIR               ?= ../$(CLONE_PACKAGE)

VERSION_FILE            ?= VERSION

ifneq ("$(wildcard $(VERSION_FILE))","")
    APP_VERSION = $(shell cat $(VERSION_FILE))
else
    APP_VERSION = $(shell git branch --show-current)
endif

LDFLAGS=-X github.com/jeremyhahn/$(PACKAGE)/app.Name=${APPNAME}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.Repository=${REPO}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.Package=${PACKAGE}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.GitBranch=${GIT_BRANCH}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.GitHash=${GIT_HASH}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.GitTag=${GIT_TAG}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.BuildUser=${USER}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.BuildDate=${BUILD_DATE}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.Version=${APP_VERSION}

GREEN=\033[0;32m
NO_COLOR=\033[0m

.PHONY: deps build build-debug build-static build-debug-static clean test initlog

default: build

env:
	@echo "ORG: \t\t\t$(ORG)"
	@echo "TARGET_OS: \t\t$(TARGET_OS)"
	@echo "TARGET_ARCH: \t\t$(TARGET_ARCH)"
	@echo "ARCH: \t\t\t$(ARCH)"
	@echo "OS: \t\t\t$(OS)"
	@echo "LONG_BITS: \t\t$(LONG_BITS)"
	@echo "GOBIN: \t\t\t$(GOBIN)"
	@echo "REPO: \t\t\t$(REPO)"
	@echo "PACKAGE: \t\t$(PACKAGE)"
	@echo "APP_VERSION: \t\t$(APP_VERSION)"
	@echo "GIT_TAG: \t\t$(GIT_TAG)"
	@echo "GIT_HASH: \t\t$(GIT_HASH)"
	@echo "GIT_BRANCH: \t\t$(GIT_BRANCH)"
	@echo "BUILD_DATE: \t\t$(BUILD_DATE)"
	@echo "CLONE_HOST: \t\t$(CLONE_HOST)"
	@echo "CLONE_OWNER: \t\t$(CLONE_OWNER)"
	@echo "CLONE_APP_NAME: \t$(CLONE_APP_NAME)"
	@echo "CLONE_PACKAGE: \t\t$(CLONE_PACKAGE)"
	@echo "CLONE_DIR: \t\t$(CLONE_DIR)"
	@echo "VERSION_FILE: \t\t$(VERSION_FILE)"

deps:
	go get

swagger:
	swag init \
		--dir webservice,webservice/v1/router,webservice/v1/response,service,model,app,config \
		--generalInfo webserver_v1.go \
		--parseDependency \
		--parseInternal \
		--parseDepth 1 \
		--output public_html/swagger

# x86_64
build:
	$(GOBIN)/go build -o $(APPNAME) -ldflags="-w -s ${LDFLAGS}"

build-debug:
	$(GOBIN)/go build -gcflags='all=-N -l' -o $(APPNAME) -gcflags='all=-N -l' -ldflags="-w -s ${LDFLAGS}"

build-static:
	$(GOBIN)/go build -o $(APPNAME) --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-debug-static:
	$(GOBIN)/go build -o $(APPNAME) -gcflags='all=-N -l' --ldflags '-extldflags -static -v ${LDFLAGS}'


# x86
build-x86:
	GOARCH=386 $(GOBIN)/go build -o $(APPNAME) -ldflags="-w -s ${LDFLAGS}"

build-x86-debug:
	GOARCH=386 $(GOBIN)/go build -gcflags='all=-N -l' -o $(APPNAME) -gcflags='all=-N -l' -ldflags="-w -s ${LDFLAGS}"

build-x86-static:
	GOARCH=386 $(GOBIN)/go build -o $(APPNAME) --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-x86-debug-static:
	GOARCH=386 $(GOBIN)/go build -o $(APPNAME) -gcflags='all=-N -l' --ldflags '-extldflags -static -v ${LDFLAGS}'


# ARM 32-bit
build-arm:
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -o $(APP) -ldflags="-w -s ${LDFLAGS}"

build-arm-static:
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -v -a -o $(APP) -v --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-arm-debug:
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -gcflags "all=-N -l" -o $(APP) --ldflags="-v $(LDFLAGS)"

build-arm-debug-static:
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -gcflags "all=-N -l" -v -a -o $(APP) -v --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'


# ARM 64-bit
build-arm64:
	CC=$(ARM_CC_64) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -o $(APP) -ldflags="-w -s ${LDFLAGS}"

build-arm64-static:
	CC=$(ARM_CC_64) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -o $(APP) --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-arm64-debug:
	CC=$(ARM_CC_64) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -gcflags "all=-N -l" -o $(APP) --ldflags="$(LDFLAGS)"

build-arm64-debug-static:
	CC=$(ARM_CC_64) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -gcflags "all=-N -l" -o $(APP) --ldflags '-extldflags -static -v ${LDFLAGS}'


clean:
	$(GOBIN)/go clean
	rm -rf $(APPNAME) \
		$(APPNAME).log \
		/usr/local/bin/$(APPNAME) \
		db/ \
		ek-cert.bin \
		pki/tpm2/ek-cert.bin
