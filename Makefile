TARGET_OS               := linux
TARGET_ARCH             := $(shell uname -m)

# Build configuration variables

# Cloud provider umbrellas, unset by default: 1 turns every service of the provider on, 0 forces every one off.
WITH_AWS                ?=
# WITH_AWS: unset = toggles decide; 1 = all AWS services (KMS, S3, compute) on; 0 = all off
WITH_GCP                ?=
# WITH_GCP: unset = toggles decide; 1 = all GCP services (KMS, GCS, compute) on; 0 = all off
WITH_AZURE              ?=
# WITH_AZURE: unset = toggles decide; 1 = all Azure services (Key Vault, Blob, compute) on; 0 = all off

# go-quicbaas build variables

# Distributed Features
WITH_RAFT               ?= 1    # Raft cluster mode (required for embedded QuicBaaS)
WITH_IAM                ?= 1    # ABAC/IAM advanced authorization

# Data Model Features
WITH_TIMESERIES         ?= 1    # Time series metrics with aggregations, retention, downsampling
WITH_VECTOR             ?= 0    # Vector database with HNSW index
WITH_RAG                ?= 0    # Retrieval Augmented Generation (requires WITH_VECTOR=1)

# API Servers
WITH_REST               ?= 1    # REST/HTTP API
WITH_QUIC               ?= 1    # QUIC protocol
WITH_MCP                ?= 1    # Model Context Protocol (LLM tools)

# WebSocket Messaging Protocols
WITH_MQTT               ?= 0    # MQTT 3.1.1/5.0 over WebSocket
WITH_AMQP               ?= 0    # AMQP 0-9-1 over WebSocket
WITH_STOMP              ?= 0    # STOMP 1.2 over WebSocket

# External Dependencies
WITH_L2_REDIS           ?= 0    # L2 Redis cache (requires external Redis)

# go-xkms build variables

# Cryptography Backends
WITH_PKCS8              ?= 1    # PKCS#8 software key storage (default backend)
WITH_TPM2               ?= 0    # TPM 2.0 hardware key support
WITH_PKCS11             ?= 0    # PKCS#11 HSM hardware support (requires CGO)
WITH_QUANTUM            ?= 0    # Quantum-safe cryptography (Dilithium, Kyber via liboqs)
WITH_FROST              ?= 1    # FROST threshold signatures (RFC 9591)

# Cloud KMS Backends (individual control)
WITH_AWS_KMS            ?= 0    # AWS Key Management Service
WITH_GCP_KMS            ?= 0    # Google Cloud KMS
WITH_AZURE_KV           ?= 0    # Azure Key Vault
WITH_VAULT              ?= 0    # HashiCorp Vault

# Cloud compute providers.
WITH_AWS_COMPUTE        ?= 0    # AWS EC2 NitroTPM compute orchestrator
WITH_GCP_COMPUTE        ?= 0    # Google Compute Engine (Shielded/Confidential VM) orchestrator
WITH_AZURE_COMPUTE      ?= 0    # Azure Trusted Launch VM orchestrator

# go-objstore backends
WITH_OBJSTORE_LOCAL     ?= 1    # Local filesystem storage (always enabled)
WITH_OBJSTORE_S3        ?= 0    # AWS S3 storage
WITH_OBJSTORE_MINIO     ?= 0    # MinIO storage
WITH_OBJSTORE_GCS       ?= 0    # Google Cloud Storage
WITH_OBJSTORE_AZURE     ?= 0    # Azure Blob Storage

# go-trusted-platform features
WITH_WEB                ?= 0    # Embed web frontend into binary (off by default for dev speed; fallback copies public_html.tar.gz into ISO)
WITH_DESKTOP            ?= 0    # Build desktop GUI (requires Wails v2)
WITH_P2P                ?= 0    # P2P/libp2p networking support
WITH_FIPS               ?= 0    # FIPS 140-3 build tag (selects the FIPS crypto implementations at compile time; pair with GODEBUG=fips140=only)

# Codecs
WITH_CODEC_JSON         ?= 1    # JSON codec
WITH_CODEC_MSGPACK      ?= 1    # MessagePack codec
WITH_CODEC_CBOR         ?= 1    # CBOR codec
WITH_CODEC_YAML         ?= 0    # YAML codec
WITH_CODEC_TOML         ?= 0    # TOML codec
WITH_CODEC_BSON         ?= 0    # BSON codec
WITH_CODEC_PROTOBUF     ?= 0    # Protocol Buffers codec

# Cloud provider umbrella expansion.
ifeq ($(strip $(WITH_AWS)),1)
    override WITH_AWS_KMS        := 1
    override WITH_OBJSTORE_S3    := 1
    override WITH_AWS_COMPUTE    := 1
else ifeq ($(strip $(WITH_AWS)),0)
    override WITH_AWS_KMS        := 0
    override WITH_OBJSTORE_S3    := 0
    override WITH_AWS_COMPUTE    := 0
endif
ifeq ($(strip $(WITH_GCP)),1)
    override WITH_GCP_KMS        := 1
    override WITH_OBJSTORE_GCS   := 1
    override WITH_GCP_COMPUTE    := 1
else ifeq ($(strip $(WITH_GCP)),0)
    override WITH_GCP_KMS        := 0
    override WITH_OBJSTORE_GCS   := 0
    override WITH_GCP_COMPUTE    := 0
endif
ifeq ($(strip $(WITH_AZURE)),1)
    override WITH_AZURE_KV       := 1
    override WITH_OBJSTORE_AZURE := 1
    override WITH_AZURE_COMPUTE  := 1
else ifeq ($(strip $(WITH_AZURE)),0)
    override WITH_AZURE_KV       := 0
    override WITH_OBJSTORE_AZURE := 0
    override WITH_AZURE_COMPUTE  := 0
endif

# Feature dependency validation
ifeq ($(strip $(WITH_RAG)),1)
    ifneq ($(strip $(WITH_VECTOR)),1)
        $(error WITH_RAG=1 requires WITH_VECTOR=1)
    endif
endif

# BUILD_TAGS, assembled from the WITH_* variables.
BUILD_TAGS := iam rest quic mcp cluster gms_pure_go opa

# go-quicbaas tags.
ifeq ($(strip $(WITH_RAFT)),1)
    BUILD_TAGS += raft
endif
ifeq ($(strip $(WITH_TIMESERIES)),1)
    BUILD_TAGS += timeseries qrdb_ts
endif
ifeq ($(strip $(WITH_VECTOR)),1)
    BUILD_TAGS += vector qrdb_vector
endif
ifeq ($(strip $(WITH_RAG)),1)
    BUILD_TAGS += rag qrdb_vector
endif

# qrdb optional features, off by default.
WITH_QRDB_SQL   ?= 0
WITH_QRDB_MYSQL ?= 0
WITH_QRDB_PGSQL ?= 0
WITH_QRDB_ETCD  ?= 0
ifeq ($(strip $(WITH_QRDB_MYSQL)),1)
    BUILD_TAGS += qrdb_mysql
    WITH_QRDB_SQL := 1
endif
ifeq ($(strip $(WITH_QRDB_PGSQL)),1)
    BUILD_TAGS += qrdb_pgsql
    WITH_QRDB_SQL := 1
endif
ifeq ($(strip $(WITH_QRDB_SQL)),1)
    BUILD_TAGS += qrdb_sql
endif
ifeq ($(strip $(WITH_QRDB_ETCD)),1)
    BUILD_TAGS += qrdb_etcd
endif
ifeq ($(strip $(WITH_MQTT)),1)
    BUILD_TAGS += quicbaas_mqtt
endif
ifeq ($(strip $(WITH_AMQP)),1)
    BUILD_TAGS += quicbaas_amqp
endif
ifeq ($(strip $(WITH_STOMP)),1)
    BUILD_TAGS += quicbaas_stomp
endif
ifeq ($(strip $(WITH_L2_REDIS)),1)
    BUILD_TAGS += l2_redis
endif

# go-xkms tags
ifeq ($(strip $(WITH_PKCS8)),1)
    BUILD_TAGS += pkcs8
endif
ifeq ($(strip $(WITH_TPM2)),1)
    BUILD_TAGS += tpm2
endif
ifeq ($(strip $(WITH_PKCS11)),1)
    BUILD_TAGS += pkcs11
endif
ifeq ($(strip $(WITH_QUANTUM)),1)
    BUILD_TAGS += quantum
endif
ifeq ($(strip $(WITH_FROST)),1)
    BUILD_TAGS += frost
endif
ifeq ($(strip $(WITH_AWS_KMS)),1)
    BUILD_TAGS += awskms
endif
ifeq ($(strip $(WITH_GCP_KMS)),1)
    BUILD_TAGS += gcpkms
endif
ifeq ($(strip $(WITH_AZURE_KV)),1)
    BUILD_TAGS += azurekv
endif
ifeq ($(strip $(WITH_VAULT)),1)
    BUILD_TAGS += vault
endif

# go-objstore tags
ifeq ($(strip $(WITH_OBJSTORE_LOCAL)),1)
    BUILD_TAGS += local
endif
ifeq ($(strip $(WITH_OBJSTORE_S3)),1)
    BUILD_TAGS += awss3
endif
ifeq ($(strip $(WITH_OBJSTORE_MINIO)),1)
    BUILD_TAGS += minio
endif
ifeq ($(strip $(WITH_OBJSTORE_GCS)),1)
    BUILD_TAGS += gcpstorage
endif
ifeq ($(strip $(WITH_OBJSTORE_AZURE)),1)
    BUILD_TAGS += azureblob
endif
# Always include objstore base tag when any backend is enabled
ifneq ($(strip $(WITH_OBJSTORE_LOCAL)$(WITH_OBJSTORE_S3)$(WITH_OBJSTORE_MINIO)$(WITH_OBJSTORE_GCS)$(WITH_OBJSTORE_AZURE)),00000)
    BUILD_TAGS += objstore
endif

# cloud compute provider tags (local compute is always compiled)
ifeq ($(strip $(WITH_AWS_COMPUTE)),1)
    BUILD_TAGS += awscompute
endif
ifeq ($(strip $(WITH_GCP_COMPUTE)),1)
    BUILD_TAGS += gcpcompute
endif
ifeq ($(strip $(WITH_AZURE_COMPUTE)),1)
    BUILD_TAGS += azurecompute
endif

# go-trusted-platform tags
ifeq ($(strip $(WITH_WEB)),1)
    BUILD_TAGS += platform_web
endif
ifeq ($(strip $(WITH_DESKTOP)),1)
    BUILD_TAGS += desktop
endif
ifeq ($(strip $(WITH_P2P)),1)
    BUILD_TAGS += platform_p2p
endif

# FIPS.
ifeq ($(strip $(WITH_FIPS)),1)
    BUILD_TAGS += fips
endif

# Codec tags
ifeq ($(strip $(WITH_CODEC_JSON)),1)
    BUILD_TAGS += codec_json
endif
ifeq ($(strip $(WITH_CODEC_MSGPACK)),1)
    BUILD_TAGS += codec_msgpack
endif
ifeq ($(strip $(WITH_CODEC_CBOR)),1)
    BUILD_TAGS += codec_cbor
endif
ifeq ($(strip $(WITH_CODEC_YAML)),1)
    BUILD_TAGS += codec_yaml
endif
ifeq ($(strip $(WITH_CODEC_TOML)),1)
    BUILD_TAGS += codec_toml
endif
ifeq ($(strip $(WITH_CODEC_BSON)),1)
    BUILD_TAGS += codec_bson
endif
ifeq ($(strip $(WITH_CODEC_PROTOBUF)),1)
    BUILD_TAGS += codec_protobuf
endif

# GO_BUILD_TAGS: the tag set CI passes to lint, build, coverage, security and integration-test.
comma                   := ,
empty                   :=
space                   := $(empty) $(empty)
GO_BUILD_TAGS_CSV       := $(subst $(space),$(comma),$(strip $(GO_BUILD_TAGS)))
ifneq ($(GO_BUILD_TAGS_CSV),)
    BUILD_TAGS += $(GO_BUILD_TAGS)
endif

# Build tag flags

BUILD_TAGS_ARG          := $(if $(strip $(BUILD_TAGS)),-tags '$(strip $(BUILD_TAGS))',)

# Integration tests need the codec tags for QUIC.
INTEGRATION_CODEC_TAGS  := codec_msgpack codec_json codec_cbor
# Integration builds carry the vector service.
INTEGRATION_VECTOR_TAGS := vector qrdb_vector
TEST_BUILD_TAGS         := integration $(INTEGRATION_CODEC_TAGS) $(INTEGRATION_VECTOR_TAGS) $(strip $(BUILD_TAGS))
TEST_BUILD_TAGS_ARG     := -tags '$(strip $(TEST_BUILD_TAGS))'

# Web embed directory
WEB_EMBED_DIR           := pkg/webserver/embed/dist

# Desktop frontend directories
DESKTOP_FRONTEND_SRC    := cmd/platformctl/frontend
DESKTOP_FRONTEND_DIST   := cmd/platformctl/frontend/dist

# The go command on PATH, or empty.
GO_CMD                  := $(shell command -v go 2>/dev/null)
ARCH                    := $(if $(GO_CMD),$(shell go env GOARCH),$(patsubst x86_64,amd64,$(patsubst aarch64,arm64,$(shell uname -m))))
OS                      := $(if $(GO_CMD),$(shell go env GOOS),$(shell uname -s | tr A-Z a-z))
LONG_BITS               := $(shell getconf LONG_BIT)

GOBIN                   := $(if $(GO_CMD),$(patsubst %/,%,$(dir $(GO_CMD))),/usr/local/go/bin)
PYTHONBIN               ?= /usr/bin/python3.8
PIPBIN                  ?= pip

GIT_REPO                ?= github.com
GIT_OWNER               ?= jeremyhahn
PACKAGE                 ?= go-trusted-platform
APPNAME                 ?= trusted-platform
PLATFORMD               ?= bin/platformd
PLATFORMCTL             ?= bin/platformctl
PLATFORMCTL_STATIC      ?= bin/platformctl-static
PLATFORM_INITRD         ?= bin/platform-initrd
GATEWAYD                ?= bin/gatewayd
DEPLOYER_PIN            ?= bin/deployer-pin
DEPLOY_AGENT            ?= bin/deploy-agent

# Cross-compiled arm64 binaries go to their own directory.
ARM64_BIN_DIR           ?= bin/aarch64
PLATFORMD_ARM64         ?= $(ARM64_BIN_DIR)/platformd
PLATFORMCTL_ARM64       ?= $(ARM64_BIN_DIR)/platformctl
PLATFORMCTL_STATIC_ARM64 ?= $(ARM64_BIN_DIR)/platformctl-static
PLATFORM_INITRD_ARM64   ?= $(ARM64_BIN_DIR)/platform-initrd
GATEWAYD_ARM64          ?= $(ARM64_BIN_DIR)/gatewayd

APP_VERSION       		?= $(shell git describe --tags --abbrev=0)
GIT_TAG                 = $(shell git describe --tags)
GIT_HASH                = $(shell git rev-parse HEAD)
GIT_BRANCH              = $(shell git branch --show-current)
GIT_TOKEN               ?=
BUILD_DATE              = $(shell date '+%Y-%m-%d_%H:%M:%S')

VERSION_FILE            ?= VERSION

ENV                     ?= dev

ifneq ("$(wildcard $(VERSION_FILE))","")
    APP_VERSION = $(shell cat $(VERSION_FILE))
else
    APP_VERSION = $(shell git branch --show-current)
endif

LDFLAGS=-X github.com/jeremyhahn/$(PACKAGE)/pkg/app.Name=${APPNAME}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.Repository=${GIT_REPO}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.Package=${PACKAGE}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.GitBranch=${GIT_BRANCH}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.GitHash=${GIT_HASH}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.GitTag=${GIT_TAG}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.BuildUser=${USER}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.BuildDate=${BUILD_DATE}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.Version=${APP_VERSION}
# gatewayd carries its own version vars, so it never links pkg/app (pkg/arch/gatewayguard_test.go).
GATEWAYD_VERSION_PKG=github.com/jeremyhahn/$(PACKAGE)/pkg/sdn/gateway/commands
LDFLAGS+= -X $(GATEWAYD_VERSION_PKG).Name=${APPNAME}
LDFLAGS+= -X $(GATEWAYD_VERSION_PKG).Repository=${GIT_REPO}
LDFLAGS+= -X $(GATEWAYD_VERSION_PKG).Package=$(PACKAGE)
LDFLAGS+= -X $(GATEWAYD_VERSION_PKG).GitBranch=${GIT_BRANCH}
LDFLAGS+= -X $(GATEWAYD_VERSION_PKG).GitHash=${GIT_HASH}
LDFLAGS+= -X $(GATEWAYD_VERSION_PKG).GitTag=${GIT_TAG}
LDFLAGS+= -X $(GATEWAYD_VERSION_PKG).BuildUser=${USER}
LDFLAGS+= -X $(GATEWAYD_VERSION_PKG).BuildDate=${BUILD_DATE}
LDFLAGS+= -X $(GATEWAYD_VERSION_PKG).Version=${APP_VERSION}

PLATFORM_DIR                ?= trusted-data
CONFIG_DIR                  ?= configs
EXAMPLE_DIR                 ?= examples
PLATFORM_CONFIG_DIR         ?= $(CONFIG_DIR)/platform

CONFIG_YAML                 ?= standalone/web-test.example.yaml

ROOT_CA                     ?= root-ca
INTERMEDIATE_CA             ?= intermediate-ca
# DOMAIN has no default; webservice-verify-tls requires it and SWAGGER_HOST follows it.
DOMAIN                      ?=

SOFTHSM_DIR                 ?= /usr/local/bin
SOFTHSM_LIB                 ?= /usr/local/lib/softhsm/libsofthsm2.so
SOFTHSM_TOKEN_DIR           ?= /var/lib/softhsm/tokens
SOFTHSM_CONFIG              ?= configs/softhsm2.conf

WEB_PUBLIC_HTML             ?= public_html
WEB_PACKAGE                 ?= trusted-platform-web
WEB_SRC                     ?= web

SWAGGER_HOST                ?= $(DOMAIN)

DOCKER_HOME                 ?= build/docker
DOCKER_REPO                 ?= docker.io
DOCKER_USER                 ?= jeremyhahn
DOCKER_BUILDER_BASE         ?= alpine
DOCKER_BUILDER_DOCKERFILE   ?= Dockerfile-$(DOCKER_BUILDER_BASE)
DOCKER_PLATFORM_BUILDER     ?= trusted-platform-builder
DOCKER_PLATFORM_BUILDER_TAG ?= latest
DOCKER_BUILDER_IMAGE        ?= $(DOCKER_REPO)/$(DOCKER_USER)/$(DOCKER_PLATFORM_BUILDER):$(DOCKER_PLATFORM_BUILDER_TAG)
DOCKER_ANSIBLE_BUILDER      ?= ansible-ee

# ISO_NAME is the artifact name `platformctl iso create` produces.
ISO_NAME                    ?= trusted-platform.iso

UID                         := $(shell id -u)
GID                         := $(shell id -g)

# Build and coverage directories
BUILD_DIR                   := build
COVERAGE_DIR                := $(BUILD_DIR)/coverage
# Pinned Go tools build from their own modules under build/tools-src/ with `go build -C`, never `go install @version`; the pin is the tool module's go.mod.
tools-module-version = $(patsubst $(2)@%,%,$(filter $(2)@%,$(subst $(2) v,$(2)@v,$(file < $(1)/go.mod))))

# golangci-lint
GOLANGCI_LINT_SRC           := build/tools-src/golangci-lint
GOLANGCI_LINT_VERSION       := $(call tools-module-version,$(GOLANGCI_LINT_SRC),github.com/golangci/golangci-lint/v2)

# actionlint, pinned and built like golangci-lint.
ACTIONLINT_SRC              := build/tools-src/actionlint
ACTIONLINT_VERSION          := $(call tools-module-version,$(ACTIONLINT_SRC),github.com/rhysd/actionlint)

# gosec, pinned and built with this module's toolchain so it can type-check the module.
GOSEC_SRC                   := build/tools-src/gosec
GOSEC_VERSION               := $(call tools-module-version,$(GOSEC_SRC),github.com/securego/gosec/v2)

# Stop at parse time on an empty tool version.
$(foreach v,GOLANGCI_LINT_VERSION ACTIONLINT_VERSION GOSEC_VERSION,$(if $($(v)),,$(error $(v) is empty: its tools module's go.mod under build/tools-src does not require the tool)))
GOSEC_DIR                   := $(BUILD_DIR)/tools/gosec-$(GOSEC_VERSION)
GOSEC                       := $(GOSEC_DIR)/gosec

# golangci-lint has no default timeout; this bounds the run.
GOLANGCI_LINT_TIMEOUT       ?= 45m

# Built from source with `go build`.
GOLANGCI_LINT_DIR           := $(BUILD_DIR)/tools/golangci-lint-$(GOLANGCI_LINT_VERSION)
GOLANGCI_LINT               := $(GOLANGCI_LINT_DIR)/golangci-lint
ACTIONLINT_DIR              := $(BUILD_DIR)/tools/actionlint-$(ACTIONLINT_VERSION)
ACTIONLINT                  := $(ACTIONLINT_DIR)/actionlint
# Per-checkout analysis cache.
export GOLANGCI_LINT_CACHE  := $(abspath $(BUILD_DIR)/tools/golangci-lint-cache)

COVERAGE_FILE               := $(COVERAGE_DIR)/coverage.out
COVERAGE_HTML               := $(COVERAGE_DIR)/coverage.html

# Test configuration
GO                          := go
GOTEST                      := $(GO) test
GOVET                       := $(GO) vet
GOFMT                       := gofmt
TEST_FLAGS                  := -v -race
# COVERAGE_THRESHOLD is a hard gate in `make coverage-report`.
COVERAGE_THRESHOLD          := 90

# gosec settings; GOSEC_CONCURRENCY bounds memory, and CI passes 2.
GOSEC_CONCURRENCY           ?= 4
GOSEC_EXCLUDE               := G102,G103,G104,G107,G109,G110,G115,G118,G122,G204,G301,G302,G304,G305,G306,G401,G402,G407,G505,G702,G703,G704

# Text colors
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[1;33m
CYAN=\033[0;36m
BLUE=\033[0;34m
BOLD=\033[1m
RESET=\033[0m
NO_COLOR=\033[0m


default: build

# Emit the assembled tag list for callers that invoke `go` directly.
.PHONY: print-build-tags
## help: List the documented make targets (every `## target: description` line)
.PHONY: help
help:
	@grep -h '^## [A-Za-z0-9_.-]*:' $(MAKEFILE_LIST) | sed 's/^## //' | sort

## print-build-tags: Print the derived build-tag set (use this, never a copied list)
print-build-tags:
	@echo '$(strip $(BUILD_TAGS))'

## print-golangci-lint-version: Print the pinned golangci-lint version
.PHONY: print-golangci-lint-version
print-golangci-lint-version:
	@echo '$(GOLANGCI_LINT_VERSION)'


.PHONY: init
init:
	sudo apt-get install -y \
		docker.io \
		virt-manager \
		docker-buildx \
		efitools \
		binfmt-support \
		qemu-user-static \
		rsync \
		pipx \
		libssl-dev
	pipx ensurepath
	pipx install virt-firmware
	sudo mkdir -p /etc/qemu/
	sudo /bin/bash -c 'echo "allow virbr0" > /etc/qemu/bridge.conf'
	sudo chmod u+s /usr/lib/qemu/qemu-bridge-helper
	$(MAKE) binfmt

# binfmt registers qemu-user for arm64 and arm with the F flag.
BINFMT_IMAGE ?= tonistiigi/binfmt@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0

.PHONY: binfmt
## binfmt: Register qemu-user (pinned tonistiigi/binfmt, qemu 10.2.3) for arm64/arm container builds
binfmt:
	docker run --rm --privileged $(BINFMT_IMAGE) --uninstall 'qemu-aarch64,qemu-arm'
	docker run --rm --privileged $(BINFMT_IMAGE) --install arm64,arm
	@grep -h interpreter /proc/sys/fs/binfmt_misc/qemu-aarch64


.PHONY: tools
tools:
	sudo apt-get install -y tpm2-tools


.PHONY: env
env:
	@$(foreach var,$(filter-out MAKE% __%,$(.VARIABLES)),\
		printf "%-35s %s\n" "$(var):" "$($(var))";)


.PHONY: run
run:
	cp $(EXAMPLE_DIR)/config.yaml config.yaml
	./$(PLATFORMD) serve \
		--debug \
		--init \
		--platform-dir trusted-data \
		--config-dir trusted-data/etc \
		--log-dir trusted-data/log \
		--ca-dir trusted-data/ca \
		--raw-so-pin 123456 \
		--raw-pin 123456 \
		--enable-mtls


# Prepare web embed directory when WITH_WEB is set
.PHONY: _web-embed-prepare
_web-embed-prepare:
ifeq ($(strip $(WITH_WEB)),1)
	@echo "$(CYAN)→ Building web frontend for embedding...$(RESET)"
	@cd sdk/javascript && npm install --silent && npm run build
	@cd $(WEB_SRC) && npm install --silent && npm run build
	@mkdir -p $(WEB_EMBED_DIR)
# The glob does not match dotfiles, which the embed directory relies on.
	@rm -rf $(WEB_EMBED_DIR)/*
# A dotfile from the web build is not copied, so not embedded.
	@cp -r $(WEB_SRC)/out/* $(WEB_EMBED_DIR)/
	@echo "$(GREEN)✓ Web frontend prepared for embedding$(RESET)"
endif

# Build desktop frontend (Svelte 5 for Wails)
.PHONY: build-desktop-frontend
build-desktop-frontend:
	@echo "$(CYAN)→ Building desktop frontend...$(RESET)"
	@cd $(DESKTOP_FRONTEND_SRC) && npm install --silent && npm run build
	@echo "$(GREEN)✓ Desktop frontend built$(RESET)"

# Build platformctl with desktop GUI (requires Wails v2)
.PHONY: build-desktop
build-desktop: build-desktop-frontend
	@mkdir -p bin
	@echo "$(CYAN)→ Building platformctl with desktop GUI...$(RESET)"
	CGO_ENABLED=1 $(GOBIN)/go build -tags "desktop $(BUILD_TAGS)" -v -o $(PLATFORMCTL) -ldflags="-w -s ${LDFLAGS}" ./cmd/platformctl
	@echo "$(GREEN)✓ Desktop build complete$(RESET)"

# Wails dev mode with hot reload (requires Wails CLI)
.PHONY: dev-desktop
dev-desktop:
	cd cmd/platformctl && wails dev -tags "desktop $(BUILD_TAGS)"

# Build without web frontend (for CI)
.PHONY: build-no-web
build-no-web:
	@mkdir -p bin
	CGO_ENABLED=1 $(GOBIN)/go build -tags "$(BUILD_TAGS)" -v -o $(PLATFORMD) -ldflags="-w -s ${LDFLAGS}" ./cmd/platformd
	CGO_ENABLED=1 $(GOBIN)/go build -tags "$(BUILD_TAGS)" -v -o $(PLATFORMCTL) -ldflags="-w -s ${LDFLAGS}" ./cmd/platformctl
	CGO_ENABLED=1 $(GOBIN)/go build -tags "$(BUILD_TAGS)" -v -o $(GATEWAYD) -ldflags="-w -s ${LDFLAGS}" ./cmd/gatewayd
	CGO_ENABLED=1 $(GOBIN)/go build -tags "$(BUILD_TAGS)" -v -o $(DEPLOYER_PIN) -ldflags="-w -s ${LDFLAGS}" ./cmd/deployer-pin

# Compile every package in both modules, with and without the build tags, emitting no binaries.
# !platform_p2p and !platform_web exist too. Every one of those files is
# The untagged pass covers the files selected by a tag's absence; platform-initrd is built by its own target.
.PHONY: build-check
## build-check: Compile all packages in both modules, tagged and untagged
build-check:
	@echo "$(CYAN)$(BOLD)→ Compiling root module, untagged (default build)$(RESET)"
	@$(GOBIN)/go build ./...
	@echo "$(CYAN)$(BOLD)→ Compiling sdk/go module, untagged (default build)$(RESET)"
	@cd sdk/go && $(GOBIN)/go build ./...
	@echo "$(CYAN)$(BOLD)→ Compiling root module with tags: $(strip $(BUILD_TAGS))$(RESET)"
	@$(GOBIN)/go build -tags "$(BUILD_TAGS)" ./...
	@echo "$(CYAN)$(BOLD)→ Compiling sdk/go module with tags: $(strip $(BUILD_TAGS))$(RESET)"
	@cd sdk/go && $(GOBIN)/go build -tags "$(BUILD_TAGS)" ./...
	@echo "$(GREEN)✓ both modules compile, tagged and untagged$(RESET)"

# Native build of platformd and platformctl, static with the web frontend; platformctl-static is a copy for netboot and disk images.
.PHONY: build
# CGO=0 with osusergo and netgo for Alpine and musl.
build: _web-embed-prepare
	@mkdir -p bin
	CGO_ENABLED=0 $(GOBIN)/go build -tags "osusergo netgo $(BUILD_TAGS)" -v -o $(PLATFORMD) --ldflags '-w -s ${LDFLAGS}' ./cmd/platformd
	CGO_ENABLED=0 $(GOBIN)/go build -tags "osusergo netgo $(BUILD_TAGS)" -v -o $(PLATFORMCTL) --ldflags '-w -s ${LDFLAGS}' ./cmd/platformctl
	cp -f $(PLATFORMCTL) $(PLATFORMCTL_STATIC)
	CGO_ENABLED=0 $(GOBIN)/go build -tags "osusergo netgo $(BUILD_TAGS)" -v -o $(GATEWAYD) --ldflags '-w -s ${LDFLAGS}' ./cmd/gatewayd
	CGO_ENABLED=0 $(GOBIN)/go build -tags "osusergo netgo $(BUILD_TAGS)" -v -o $(DEPLOYER_PIN) --ldflags '-w -s ${LDFLAGS}' ./cmd/deployer-pin

.PHONY: build-debug
build-debug: _web-embed-prepare
	@mkdir -p bin
	CGO_ENABLED=1 $(GOBIN)/go build -tags "$(BUILD_TAGS)" -v -o $(PLATFORMD) -gcflags='all=-N -l' --ldflags '-linkmode external -extldflags -static -v ${LDFLAGS}' ./cmd/platformd
	CGO_ENABLED=1 $(GOBIN)/go build -tags "$(BUILD_TAGS)" -v -o $(PLATFORMCTL) -gcflags='all=-N -l' --ldflags '-linkmode external -extldflags -static -v ${LDFLAGS}' ./cmd/platformctl

.PHONY: build-static
build-static: build
	@echo "build-static target is deprecated. Use 'make build' instead (now produces static binaries by default)."

.PHONY: build-debug-static
build-debug-static: build-debug
	@echo "build-debug-static target is deprecated. Use 'make build-debug' instead (now produces static binaries by default)."

# Cross-compile arm64: pure Go, the native tag set, statically linked.
.PHONY: build-arm64
## build-arm64: Cross-compile platformd, platformctl and platformctl-static for linux/arm64 into bin/aarch64
build-arm64: _web-embed-prepare
	@mkdir -p $(ARM64_BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBIN)/go build -tags "osusergo netgo $(BUILD_TAGS)" -v -o $(PLATFORMD_ARM64) --ldflags '-w -s ${LDFLAGS}' ./cmd/platformd
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBIN)/go build -tags "osusergo netgo $(BUILD_TAGS)" -v -o $(PLATFORMCTL_ARM64) --ldflags '-w -s ${LDFLAGS}' ./cmd/platformctl
	cp -f $(PLATFORMCTL_ARM64) $(PLATFORMCTL_STATIC_ARM64)

.PHONY: build-arm64-static
build-arm64-static: build-arm64
	@echo "build-arm64-static target is deprecated. Use 'make build-arm64' instead (a CGO_ENABLED=0 cross build is already static)."

.PHONY: build-arm64-debug
build-arm64-debug: _web-embed-prepare
	@mkdir -p $(ARM64_BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBIN)/go build -tags "osusergo netgo $(BUILD_TAGS)" -v -o $(PLATFORMD_ARM64) -gcflags='all=-N -l' --ldflags '${LDFLAGS}' ./cmd/platformd
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBIN)/go build -tags "osusergo netgo $(BUILD_TAGS)" -v -o $(PLATFORMCTL_ARM64) -gcflags='all=-N -l' --ldflags '${LDFLAGS}' ./cmd/platformctl
	cp -f $(PLATFORMCTL_ARM64) $(PLATFORMCTL_STATIC_ARM64)

.PHONY: build-arm64-debug-static
build-arm64-debug-static: build-arm64-debug
	@echo "build-arm64-debug-static target is deprecated. Use 'make build-arm64-debug' instead (a CGO_ENABLED=0 cross build is already static)."


# platform-initrd: the minimal initramfs binary

# Initrd build tags: osusergo and netgo without cgo, local for the go-objstore local backend.
INITRD_BUILD_TAGS       := osusergo,netgo,local

.PHONY: platform-initrd
platform-initrd:
	@mkdir -p bin
	@echo "Building platform-initrd (size-optimized static binary for initramfs)..."
	CGO_ENABLED=0 $(GOBIN)/go build -tags "$(INITRD_BUILD_TAGS)" \
		-ldflags="-s -w ${LDFLAGS}" \
		-o $(PLATFORM_INITRD) ./cmd/platform-initrd
	@echo "Binary size: $$(du -h $(PLATFORM_INITRD) | cut -f1)"

.PHONY: platform-initrd-debug
platform-initrd-debug:
	@mkdir -p bin
	CGO_ENABLED=0 $(GOBIN)/go build -tags "$(INITRD_BUILD_TAGS)" \
		-gcflags='all=-N -l' \
		-ldflags="${LDFLAGS}" \
		-o $(PLATFORM_INITRD) ./cmd/platform-initrd
	@echo "Binary size: $$(du -h $(PLATFORM_INITRD) | cut -f1)"

.PHONY: platform-initrd-static
platform-initrd-static: platform-initrd
	@echo "platform-initrd-static target is deprecated. Use 'make platform-initrd' instead (already produces static binaries)."

# Cross-compile arm64 for initrd into $(ARM64_BIN_DIR).
.PHONY: platform-initrd-arm64
## platform-initrd-arm64: Cross-compile platform-initrd for linux/arm64 into bin/aarch64
platform-initrd-arm64:
	@mkdir -p $(ARM64_BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -tags "$(INITRD_BUILD_TAGS)" \
		-ldflags="-s -w ${LDFLAGS}" \
		-o $(PLATFORM_INITRD_ARM64) ./cmd/platform-initrd
	@echo "Binary size: $$(du -h $(PLATFORM_INITRD_ARM64) | cut -f1)"

.PHONY: platform-initrd-arm64-static
platform-initrd-arm64-static: platform-initrd-arm64
	@echo "platform-initrd-arm64-static target is deprecated. Use 'make platform-initrd-arm64' instead (a CGO_ENABLED=0 cross build is already static)."


# gatewayd: the standalone SDN gateway binary

# Gateway daemon build tags - core SDN functionality
GATEWAYD_BUILD_TAGS     := $(BUILD_TAGS)

.PHONY: build-gatewayd
build-gatewayd:
	@mkdir -p bin
	@echo "Building gatewayd (SDN gateway daemon - static)..."
	CGO_ENABLED=1 $(GOBIN)/go build -tags "$(GATEWAYD_BUILD_TAGS)" \
		--ldflags="-w -s -linkmode external -extldflags '-static' -v ${LDFLAGS}" \
		-o $(GATEWAYD) ./cmd/gatewayd
	@echo "Binary size: $$(du -h $(GATEWAYD) | cut -f1)"

.PHONY: build-gatewayd-debug
build-gatewayd-debug:
	@mkdir -p bin
	@echo "Building gatewayd-debug (with debug symbols - static)..."
	CGO_ENABLED=1 $(GOBIN)/go build -tags "$(GATEWAYD_BUILD_TAGS)" \
		-gcflags='all=-N -l' \
		--ldflags="-linkmode external -extldflags '-static' -v ${LDFLAGS}" \
		-o $(GATEWAYD) ./cmd/gatewayd
	@echo "Binary size: $$(du -h $(GATEWAYD) | cut -f1)"

.PHONY: build-gatewayd-static
build-gatewayd-static: build-gatewayd
	@echo "build-gatewayd-static target is deprecated. Use 'make build-gatewayd' instead (now produces static binaries by default)."

# Cross-compile arm64 for gatewayd into $(ARM64_BIN_DIR).
.PHONY: build-gatewayd-arm64
## build-gatewayd-arm64: Cross-compile gatewayd for linux/arm64 into bin/aarch64
build-gatewayd-arm64:
	@mkdir -p $(ARM64_BIN_DIR)
	@echo "Building gatewayd for ARM64 (static, pure Go)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -tags "osusergo netgo $(GATEWAYD_BUILD_TAGS)" \
		--ldflags="-w -s ${LDFLAGS}" \
		-o $(GATEWAYD_ARM64) ./cmd/gatewayd
	@echo "Binary size: $$(du -h $(GATEWAYD_ARM64) | cut -f1)"

.PHONY: build-gatewayd-arm64-static
build-gatewayd-arm64-static: build-gatewayd-arm64
	@echo "build-gatewayd-arm64-static target is deprecated. Use 'make build-gatewayd-arm64' instead (a CGO_ENABLED=0 cross build is already static)."
# ==============================================================================

# Deployer pin: the SSH host-key pin provisioning tool

.PHONY: build-deployer-pin
build-deployer-pin:
	@mkdir -p bin
	@echo "Building deployer-pin (SSH host-key pin tool - static)..."
	CGO_ENABLED=0 $(GOBIN)/go build -tags "osusergo netgo $(BUILD_TAGS)" \
		--ldflags '-w -s ${LDFLAGS}' \
		-o $(DEPLOYER_PIN) ./cmd/deployer-pin
	@echo "Binary size: $$(du -h $(DEPLOYER_PIN) | cut -f1)"
# ==============================================================================

# QUIC deploy agent

.PHONY: build-deploy-agent
build-deploy-agent:
	@mkdir -p bin
	@echo "Building deploy-agent (QUIC deploy agent - static)..."
	CGO_ENABLED=0 $(GOBIN)/go build -tags "osusergo netgo $(BUILD_TAGS)" \
		--ldflags '-w -s ${LDFLAGS}' \
		-o $(DEPLOY_AGENT) ./cmd/deploy-agent
	@echo "Binary size: $$(du -h $(DEPLOY_AGENT) | cut -f1)"
# ==============================================================================

# Build public_html in the devcontainer.
.PHONY: build-public-html
build-public-html:
	@echo "Building WebUI using devcontainer (monorepo web/ directory)..."
	@# Ensure devcontainer image exists
	@if ! docker images | grep -q "$(DEVCONTAINER_IMAGE)"; then \
		echo "Building devcontainer image (first time only)..."; \
		$(MAKE) build-devcontainer; \
	fi
	@# Run the build inside devcontainer (web/ is now part of the monorepo)
	docker run --rm \
		-v $(CURDIR):/workspace \
		-w /workspace \
		-e HOME=/root \
		$(DEVCONTAINER_IMAGE) \
		/bin/bash -c '\
			set -e; \
			echo "[WebUI] Starting build (monorepo web/ directory)..."; \
			\
			# Clean up previous builds \
			rm -rf $(WEB_PUBLIC_HTML)/ pkg/$(WEB_PUBLIC_HTML)/; \
			mkdir -p $(WEB_PUBLIC_HTML)/ pkg/$(WEB_PUBLIC_HTML)/; \
			\
			# Build swagger docs \
			echo "[WebUI] Generating Swagger/OpenAPI documentation..."; \
			/go/bin/swag init \
				--dir pkg/webservice,pkg/webservice/v1/jwt,pkg/webservice/v1/router,pkg/webservice/v1/response,pkg/store/datastore/entities,pkg/app,pkg/config,pkg/crypto/argon2 \
				--generalInfo webserver_v1.go \
				--parseDependency \
				--parseInternal \
				--parseDepth 1 \
				--output $(WEB_PUBLIC_HTML)/swagger || true; \
			\
			# Download swagger-ui \
			echo "[WebUI] Setting up Swagger UI..."; \
			mkdir -p $(WEB_PUBLIC_HTML)/swagger; \
			git clone --depth=1 https://github.com/swagger-api/swagger-ui.git /tmp/swagger-ui && \
				mv /tmp/swagger-ui/dist/* $(WEB_PUBLIC_HTML)/swagger/ && \
				rm -rf /tmp/swagger-ui; \
			\
			# Build the Next.js web project from monorepo web/ directory \
			echo "[WebUI] Installing dependencies..."; \
			cd /workspace/$(WEB_SRC) && npm ci 2>/dev/null || npm install; \
			echo "[WebUI] Building Next.js application..."; \
			cd /workspace/$(WEB_SRC) && npm run build; \
			\
			# Copy build output to public_html \
			echo "[WebUI] Copying build artifacts..."; \
			cp -R /workspace/$(WEB_SRC)/out/* /workspace/$(WEB_PUBLIC_HTML)/; \
			\
			# Create tarball for ISO building \
			echo "[WebUI] Creating public_html.tar.gz..."; \
			cd /workspace && tar czf public_html.tar.gz $(WEB_PUBLIC_HTML)/; \
			\
			echo "[WebUI] Build complete!"; \
			echo "[WebUI] Output: $(WEB_PUBLIC_HTML)/ and public_html.tar.gz"; \
		'
	@echo "WebUI build complete: public_html.tar.gz"


# Build public_html on host (legacy - use build-public-html instead for consistent builds)
.PHONY: build-public-html-host
build-public-html-host:
	# Start with a clean directory
	rm -rf $(WEB_PUBLIC_HTML)/ pkg/$(WEB_PUBLIC_HTML)/
	mkdir -p $(WEB_PUBLIC_HTML)/ pkg/$(WEB_PUBLIC_HTML)/

	# Build the swagger / OpenAPI docs
	make swagger
	make swagger-ui

	# Configure SwaggerInfo
	sed -i '/var SwaggerInfo = &swag.Spec{/,/}}/c\var SwaggerInfo = \&swag.Spec{\n\tVersion:          "$(APP_VERSION)",\n\tHost:             "$(SWAGGER_HOST)",\n\tBasePath:         "/api/v1",\n\tSchemes:          []string{},\n\tTitle:            "Trusted Platform",\n\tDescription:      "The Trusted Platform RESTful Web Services API",\n\tInfoInstanceName: "swagger",\n\tSwaggerTemplate:  docTemplate,\n\tLeftDelim:        "{{",\n\tRightDelim:       "}}",' $(WEB_PUBLIC_HTML)/swagger/docs.go

	# Set the version annotation
	sed -i 's|@version .*|@version $(APP_VERSION)|g' pkg/webservice/webserver_v1.go

	# Copy into the pkg directory for debugging
	-cp -R $(WEB_PUBLIC_HTML)/swagger pkg/$(WEB_PUBLIC_HTML)/

	# Build the Next.js web project from monorepo web/ directory
	cd $(WEB_SRC) && \
		npm install && \
		npm run build && \
		cp -R out/* ../$(WEB_PUBLIC_HTML)/

	# Copy into the pkg directory for debugging
	cp -R $(WEB_SRC)/out/* pkg/$(WEB_PUBLIC_HTML)/

	# Create tarball for ISO building
	tar czf public_html.tar.gz $(WEB_PUBLIC_HTML)/

.PHONY: swagger
swagger:
	~/go/bin/swag init \
		--dir pkg/webservice,pkg/webservice/v1/jwt,pkg/webservice/v1/router,pkg/webservice/v1/response,pkg/store/datastore/entities,pkg/app,pkg/config,pkg/crypto/argon2 \
		--generalInfo webserver_v1.go \
		--parseDependency \
		--parseInternal \
		--parseDepth 1 \
		--output $(WEB_PUBLIC_HTML)/swagger

.PHONY: swagger-ui
swagger-ui:
	mkdir -p $(WEB_PUBLIC_HTML)/swagger
	git clone --depth=1 https://github.com/swagger-api/swagger-ui.git && \
		mv swagger-ui/dist/* $(WEB_PUBLIC_HTML)/swagger && \
		rm -rf swagger-ui
	sed -i '/var SwaggerInfo = &swag.Spec{/,/}}/c\var SwaggerInfo = \&swag.Spec{\n\tVersion:          "$(APP_VERSION)",\n\tHost:             "$(SWAGGER_HOST)",\n\tBasePath:         "/api/v1",\n\tSchemes:          []string{},\n\tTitle:            "Trusted Platform",\n\tDescription:      "The Trusted Platform RESTful Web Services API",\n\tInfoInstanceName: "swagger",\n\tSwaggerTemplate:  docTemplate,\n\tLeftDelim:        "{{",\n\tRightDelim:       "}}",' $(WEB_PUBLIC_HTML)/swagger/docs.go
	sed -i 's|@version .*|@version $(APP_VERSION)|g' pkg/webservice/webserver_v1.go


# Frontend (Next.js) in web/

.PHONY: web-install
web-install:
	@echo "[Web] Installing npm dependencies..."
	cd $(WEB_SRC) && npm install

# web resolves trusted-platform-sdk from sdk/javascript/dist.
.PHONY: web-sdk-build
web-sdk-build:
	@echo "[Web] Building trusted-platform-sdk..."
	cd sdk/javascript && npm install --silent && npm run build

.PHONY: web-build
web-build: web-sdk-build
	@echo "[Web] Building Next.js frontend..."
	cd $(WEB_SRC) && npm run build
	@echo "[Web] Copying build output to $(WEB_PUBLIC_HTML)/"
	mkdir -p $(WEB_PUBLIC_HTML)
	cp -R $(WEB_SRC)/out/* $(WEB_PUBLIC_HTML)/
	tar czf public_html.tar.gz $(WEB_PUBLIC_HTML)/

.PHONY: web-test
web-test:
	@echo "[Web] Running Playwright E2E tests..."
	cd $(WEB_SRC) && npm run test:e2e

# Playwright against a real platformd with the console embedded, on the TPM simulator, with real WebAuthn ceremonies.
WEB_E2E_BUILD ?= 1
.PHONY: web-e2e
web-e2e: web-deps
ifeq ($(strip $(WEB_E2E_BUILD)),1)
	$(MAKE) web-e2e-platformd WITH_WEB=1
endif
	@echo "[Web] Running Playwright against a real platformd..."
	cd $(WEB_SRC) && E2E_PORT=$(E2E_PORT) PLATFORMD_BIN=$(abspath $(PLATFORMD)) \
		npx playwright test --config playwright.real-server.config.ts

# The web-e2e daemon: bin/platformd with the console, cgo and the tpm_simulator tag.
.PHONY: web-e2e-platformd
web-e2e-platformd: _web-embed-prepare
	@mkdir -p bin
	CGO_ENABLED=1 $(GOBIN)/go build -tags "tpm_simulator $(BUILD_TAGS)" -o $(PLATFORMD) --ldflags '-w -s ${LDFLAGS}' ./cmd/platformd

# vitest over web/src/**/*.test.ts(x), no server.
.PHONY: web-test-unit
web-test-unit:
	@echo "[Web] Running unit tests (vitest)..."
	cd $(WEB_SRC) && npm run test:unit

.PHONY: web-test-ui
web-test-ui:
	@echo "[Web] Running Playwright E2E tests with UI..."
	cd $(WEB_SRC) && npm run test:e2e:ui

# WebAuthn E2E tests; pass FRONTEND_URL and HEADED via env vars, e.g. make web-test-webauthn FRONTEND_URL=https://server.example.com:8443 HEADED=1
.PHONY: web-test-webauthn
web-test-webauthn:
	cd $(WEB_SRC) && $(MAKE) test-webauthn

# CI-shaped web targets use `npm ci` for a reproducible run.
.PHONY: web-deps
web-deps:
	@echo "[Web] Installing from lockfiles and building trusted-platform-sdk..."
	cd sdk/javascript && npm ci && npm run build
	cd $(WEB_SRC) && npm ci

# eslint only.
.PHONY: web-lint
web-lint:
	@echo "[Web] Running ESLint..."
	cd $(WEB_SRC) && npm run lint

.PHONY: web-typecheck
web-typecheck:
	@echo "[Web] Running TypeScript checks..."
	cd $(WEB_SRC) && npm run typecheck

# `next build` only.
.PHONY: web-build-check
web-build-check:
	@echo "[Web] Building Next.js frontend (check only)..."
	cd $(WEB_SRC) && npm run build

.PHONY: web-clean
web-clean:
	@echo "[Web] Cleaning frontend build artifacts..."
	rm -rf $(WEB_SRC)/.next $(WEB_SRC)/out $(WEB_SRC)/node_modules $(WEB_EMBED_DIR)/*

# =============================================================================


# gRPC proto generation
.PHONY: proto proto-lint proto-clean

proto:
	@echo "Generating gRPC code from proto files..."
	cd pkg/api/grpc && buf generate
	@echo "gRPC code generated in sdk/go/gen/"

proto-lint:
	@echo "Linting proto files..."
	cd pkg/api/grpc/proto && buf lint

proto-clean:
	@echo "Cleaning generated gRPC code..."
	rm -rf sdk/go/gen/


.PHONY: clean
clean:
	cd pkg; \
	$(GOBIN)/go clean
	rm -rf \
		$(PLATFORMD) \
		$(PLATFORMD)-* \
		$(PLATFORM_API) \
		$(PLATFORM_API)-* \
		$(PLATFORMCTL) \
		$(PLATFORMCTL)-* \
		$(PLATFORM_INITRD) \
		$(PLATFORM_INITRD)-* \
		$(GATEWAYD) \
		$(GATEWAYD)-* \
		$(DEPLOYER_PIN) \
		$(DEPLOYER_PIN)-* \
		*.img \
		*.iso \
		*.test \
		*.qcow2 \
		*.log \
		/usr/local/bin/$(PLATFORMD) \
		$(PLATFORM_DIR) \
		$(WEB_PUBLIC_HTML) \
		$(WEB_PUBLIC_HTML).tar.gz \
		build/docker/trusted-platform/platformd \
		build/docker/trusted-platform/platformd-debug \
		build/docker/trusted-platform/trusted-data \
		build/docker/pxe-server/*.qcow2 \
		build/docker/pxe-server/volume \
		examples/tss/attestor/$(PLATFORM_DIR) \
		examples/tss/verifier/$(PLATFORM_DIR) \
		examples/client/$(PLATFORM_DIR) \
		examples/server/$(PLATFORM_DIR) \
		pkg/$(PLATFORM_DIR) \
		pkg/config.yaml \
		pkg/$(WEB_PUBLIC_HTML) \
		pkg/platform/testdata \
		pkg/store/object/testdata \
		pkg/store/certstore/testdata \
		config.yaml

# Platform Web Services
.PHONY: webservice
webservice: build-debug config
	./$(PLATFORMD) --init serve --enable-mtls

.PHONY: webservice-verify-tls
webservice-verify-tls:
	@test -n "$(DOMAIN)" || { echo "webservice-verify-tls: set DOMAIN to the deployment domain the CA was issued for" >&2; exit 2; }
	openssl s_client \
		-connect localhost:8443 \
		-showcerts \
		-servername localhost \
		-CAfile pkg/$(PLATFORM_DIR)/ca/$(INTERMEDIATE_CA).$(DOMAIN)/x509/$(ROOT_CA).$(DOMAIN).pkcs8.rsa.pem \
		| openssl x509 -noout -text


# SoftHSM
.PHONY: softhsm-init
softhsm-init:
	export SOFTHSM_CONF=$(SOFTHSM_CONFIG); \
	chown $(USER):$(USER) $(SOFTHSM_TOKEN_DIR); \
	$(SOFTHSM_DIR)/softhsm2-util \
		--init-token \
		--slot 0 \
		--label test \
		--so-pin 1234 \
		--pin 5678 ; \
	$(SOFTHSM_DIR)/softhsm2-util --show-slots

# Tests. TEST_SKIP quarantines individual tests, each with a reason.
TEST_SKIP := TestPickBootSourceOverrideTarget_X10WithCDDVDAlias|TestPickBootSourceOverrideTarget_X10PrefersVendorUEFIOverUSBCD|TestX10SDVBootMediaType|TestSupermicroManufacturerWideBootMediaType|TestResolveVeloCloudEDGE840

# SHARDS and SHARD split the unit packages round-robin: `make test-race SHARD=1 SHARDS=4` runs the second of four.
SHARDS ?= 1
SHARD ?= 0
SHARD_PICK = awk -v n=$(SHARDS) -v s=$(SHARD) '(NR - 1) % n == s'

.PHONY: test
test: check-insecure-tls check-go-build-tags
	@echo "Running all unit tests..."
	go test -tags "$(BUILD_TAGS)" -v -skip "$(TEST_SKIP)" $$({ go list ./pkg/... ./cmd/... 2>/dev/null | grep -v -E "$(TEST_EXCLUDE)"; printf '%s\n' $(TEST_UNIT_PKGS); } | $(SHARD_PICK))
	$(if $(filter 0,$(strip $(SHARD))),$(MAKE) --no-print-directory test-noopa)

.PHONY: test-fips
## test-fips: FIPS 140-3 suite: build ./... and run `make test`, both with the fips tag under GODEBUG=fips140=only
test-fips: SHELL := /bin/bash
test-fips:
	GOFIPS140=latest GODEBUG=fips140=only go build -tags "$$($(MAKE) -s --no-print-directory print-build-tags WITH_FIPS=1)" ./...
	@set -o pipefail; status=0; \
	tags="$$($(MAKE) -s --no-print-directory print-build-tags WITH_FIPS=1)"; \
	GOFIPS140=latest GODEBUG=fips140=only $(MAKE) --no-print-directory test WITH_FIPS=1 2>&1 | tee "$(FIPS_LOG)" || status=$$?; \
	if [ $$status -ne 0 ]; then \
		echo "FIPS unit tests failed (status $$status); checking the failures against $(FIPS_FOREIGN_BASELINE) (ruling 125)"; \
		status=0; \
		GOFIPS140=latest GODEBUG=fips140=only $(GO) run ./scripts/foreignfailures -job fips \
			-baseline $(FIPS_FOREIGN_BASELINE) -tags "$$tags" -skip-tests "$(TEST_SKIP)" "$(FIPS_LOG)" || status=$$?; \
	fi; \
	exit $$status

.PHONY: test-noopa
## test-noopa: Unit tests of the !opa build: the OPA engine packages and their consumers with opa dropped from BUILD_TAGS
# !opa tests. This target runs every package that splits on the tag, and
# Every package that imports pkg/policy/opa, with the required tags minus opa.
NOOPA_TAGS := $(filter-out opa,$(BUILD_TAGS))
NOOPA_PKGS := ./pkg/policy/opa/ ./pkg/compute/container/ \
	./pkg/sdn/gateway/proxysvc/ ./pkg/sdn/gateway/services/vpn/ ./pkg/sdn/gateway/ \
	./pkg/vpn/... ./pkg/api/daemon/... ./pkg/sdn/gateway/commands/...
test-noopa:
	go test -count=1 -tags "$(NOOPA_TAGS)" -skip "$(TEST_SKIP)" $(NOOPA_PKGS)

.PHONY: test-pkg
## test-pkg: Run unit tests for one package with the derived tag set, e.g. make test-pkg PKG=./pkg/api/daemon/
test-pkg:
	@if [ -z "$(strip $(PKG))" ]; then \
		echo "$(RED)$(BOLD)PKG is required$(RESET)"; \
		echo "  usage: make test-pkg PKG=./pkg/api/daemon/"; \
		echo "         make test-pkg PKG=./pkg/api/daemon/ TESTFLAGS='-run TestFoo -v'"; \
		exit 2; \
	fi
	set -f; testflags='$(subst ','\'',$(TESTFLAGS))'; \
	go test -tags "$(BUILD_TAGS)" -skip "$(TEST_SKIP)" $$testflags $(PKG)

# Tagged as test-pkg is.
.PHONY: test-sdk-go
## test-sdk-go: Run Go SDK unit tests (sdk/go module)
test-sdk-go:
	@echo "Running Go SDK unit tests..."
	cd sdk/go && go test -tags "$(BUILD_TAGS)" ./...

.PHONY: sdk-consumer-check
## sdk-consumer-check: Build sdk/go from a throwaway consumer module, without the root module
sdk-consumer-check:
	@scripts/sdk-consumer-check.sh

.PHONY: test-sdk-js
## test-sdk-js: Run JavaScript SDK unit tests (sdk/javascript vitest suite)
test-sdk-js:
	@echo "Running JavaScript SDK unit tests..."
	cd sdk/javascript && npm ci && npm test

.PHONY: lint-sdk-js
## lint-sdk-js: Lint the JavaScript SDK (sdk/javascript eslint)
lint-sdk-js:
	@echo "Linting JavaScript SDK..."
	cd sdk/javascript && npm ci && npm run lint

.PHONY: test-legacy
test-legacy: test-crypto test-webservice

# test-ca and test-tpm live in go-trusted-ca and go-xkms.

.PHONY: test-crypto
test-crypto:
	# tag-independent
	cd pkg/crypto/aesgcm && go test -v
	# tag-independent
	cd pkg/crypto/argon2 && go test -v

.PHONY: test-store
test-store: test-store-datastore

# test-store-pkcs11 and test-store-tpm2 live in go-xkms.

.PHONY: test-store-datastore
test-store-datastore:
	cd pkg/store/datastore && \
		# tag-independent
		go test -v
	cd pkg/store/datastore/kvstore && \
		# tag-independent
		go test -v

# QuicBaaS unit tests on mock storage, no Raft.
.PHONY: test-quicbaas
test-quicbaas:
	@echo "Running QuicBaaS unit tests (fast, no Raft)..."
	go test -v -count=1 -tags "$(BUILD_TAGS)" -run "Test.*_Mock|^TestMockStorage|^TestErr|^TestDefault|^TestConfig|^TestConsistency|^TestParse|^TestGetFree|^TestAllErrors" ./pkg/storage/quicbaas/...

# QuicBaaS unit tests with coverage, no Raft.
.PHONY: test-quicbaas-coverage
test-quicbaas-coverage:
	@echo "Running QuicBaaS unit tests with coverage (fast, no Raft)..."
	@echo "Note: client.go and factory.go (0%) require Raft - tested via test-quicbaas-coverage-full"
	go test -count=1 -tags "$(BUILD_TAGS)" -run "Test.*_Mock|^TestMockStorage|^TestErr|^TestDefault|^TestConfig|^TestConsistency|^TestParse|^TestGetFree|^TestAllErrors" -coverprofile=/tmp/quicbaas.cover ./pkg/storage/quicbaas/...
	go tool cover -func=/tmp/quicbaas.cover | tail -1

# QuicBaaS full coverage including the Raft tests, run serially.
.PHONY: test-quicbaas-coverage-full
test-quicbaas-coverage-full:
	@echo "Running all QuicBaaS tests with coverage (includes Raft, serial, ~3 min)..."
	go test -count=1 -tags "$(BUILD_TAGS)" -parallel 1 -timeout 10m -coverprofile=/tmp/quicbaas.cover ./pkg/storage/quicbaas/...
	go tool cover -func=/tmp/quicbaas.cover | tail -1

# QuicBaaS All Tests (includes slow Raft tests - runs serially)
.PHONY: test-quicbaas-all
test-quicbaas-all:
	@echo "Running all QuicBaaS tests (includes Raft, serial, ~3 min)..."
	go test -v -count=1 -tags "$(BUILD_TAGS)" -parallel 1 -timeout 10m ./pkg/storage/quicbaas/...

.PHONY: integration-test-ca-quicbaas-adapter
## integration-test-ca-quicbaas-adapter: Run CA QuicBaaS adapter integration tests in development container
integration-test-ca-quicbaas-adapter: build-devcontainer
	@echo "Running CA QuicBaaS adapter integration tests in development container..."
	@echo "Build tags: $(TEST_BUILD_TAGS)"
	@docker run --rm --privileged \
		--name go-trusted-platform-ca-quicbaas-adapter-test \
		--tmpfs /tmp:exec,mode=1777 \
		-v $(PWD):/workspace \
		$(DOCKER_MODULE_MOUNTS) \
		-w /workspace \
		-e CGO_ENABLED=0 \
		$(DEVCONTAINER_IMAGE) \
		go test -v $(TEST_BUILD_TAGS_ARG) -count=1 -parallel 1 -timeout 10m ./pkg/store/datastore/...

# DNS Integration Tests
.PHONY: integration-test-dns
## integration-test-dns: Run DNS integration tests (zone CRUD, record types, attestation, DANE)
integration-test-dns: build-devcontainer
	$(call run-integration-suite,dns)

.PHONY: integration-test-dns-local
## integration-test-dns-local: Run DNS integration tests locally (no container)
integration-test-dns-local:
	@echo "Running DNS integration tests locally..."
	@echo "Build tags: $(TEST_BUILD_TAGS)"
	go test -v $(TEST_BUILD_TAGS_ARG) -count=1 -timeout=10m ./test/integration/dns/...

# Compute Orchestration Tests
.PHONY: test-compute
test-compute:
	@echo "Running compute orchestration unit tests..."
	# tag-independent
	go test -v -count=1 ./pkg/compute/...

.PHONY: test-compute-coverage
test-compute-coverage:
	@echo "Running compute orchestration tests with coverage..."
	# tag-independent
	go test -count=1 -coverprofile=/tmp/compute.cover ./pkg/compute/...
	go tool cover -func=/tmp/compute.cover | tail -1

.PHONY: coverage-compute
coverage-compute: test-compute-coverage
	@mkdir -p $(COVERAGE_DIR)
	@go tool cover -html=/tmp/compute.cover -o build/coverage/compute.html
	@echo "Coverage report: build/coverage/compute.html"

## bench-compute: Run compute orchestration benchmarks
.PHONY: bench-compute
bench-compute:
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/compute/...

# BMC Tests
## test-bmc: Run BMC package unit tests
.PHONY: test-bmc
test-bmc:
	# tag-independent
	go test -count=1 -timeout 120s \
		./pkg/bmc/... \
		./pkg/app/bmc_cert_test.go \
		./pkg/cli/commands/bmc/...

## coverage-bmc: BMC package coverage report
.PHONY: coverage-bmc
coverage-bmc:
	# tag-independent
	go test -count=1 -timeout 120s -coverprofile=coverage-bmc.out \
		./pkg/bmc/... \
		./pkg/cli/commands/bmc/...
	go tool cover -func=coverage-bmc.out | tail -5

# AVR firmware attestation tests: a fake link through the real trusted-firmware codec, no device.
## test-avr-attestation: Run AVR firmware attestation provider unit tests
.PHONY: test-avr-attestation
test-avr-attestation:
	# tag-independent
	go test -count=1 -timeout 120s ./pkg/firmware/avr/...

## coverage-avr-attestation: AVR firmware attestation coverage report
.PHONY: coverage-avr-attestation
coverage-avr-attestation:
	# tag-independent
	go test -count=1 -timeout 120s -coverprofile=coverage-avr-attestation.out \
		./pkg/firmware/avr/...
	go tool cover -func=coverage-avr-attestation.out | tail -5

## bench-avr-attestation: Benchmark the AVR firmware attestation provider
.PHONY: bench-avr-attestation
bench-avr-attestation:
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/firmware/avr/...

## integration-test-bmc: Run BMC multi-protocol integration tests in devcontainer
.PHONY: integration-test-bmc
integration-test-bmc: build-devcontainer
	$(call run-integration-suite,bmc)

## integration-test-ca: Run CA multi-protocol integration tests in devcontainer
.PHONY: integration-test-ca
integration-test-ca: build-devcontainer
	$(call run-integration-suite,ca)

## integration-test-ceremony: Run ceremony multi-protocol integration tests in devcontainer
.PHONY: integration-test-ceremony
integration-test-ceremony: build-devcontainer
	$(call run-integration-suite,ceremony)

## integration-test-piv: Run PIV multi-protocol integration tests in devcontainer
.PHONY: integration-test-piv
integration-test-piv: build-devcontainer
	$(call run-integration-suite,piv)

## integration-test-luks: Run LUKS multi-protocol integration tests in devcontainer
.PHONY: integration-test-luks
integration-test-luks: build-devcontainer
	$(call run-integration-suite,luks)

## integration-test-fido2: Run FIDO2 multi-protocol integration tests in devcontainer
.PHONY: integration-test-fido2
integration-test-fido2: build-devcontainer
	$(call run-integration-suite,fido2)

## integration-test-proxy: Run reverse-proxy multi-protocol + gatewayd traffic integration tests in devcontainer
.PHONY: integration-test-proxy
integration-test-proxy: build-devcontainer
	$(call run-integration-suite,proxy)

## test-cloud-compute-aws: Run AWS EC2 NitroTPM live cloud tests (opt-in; needs AWS credentials and COMPUTE_AWS_*)
.PHONY: test-cloud-compute-aws
test-cloud-compute-aws:
	@echo "$(CYAN)→ Running AWS NitroTPM compute cloud tests (real AWS, may incur cost)$(RESET)"
	COMPUTE_AWS_LIVE=1 $(GOBIN)/go test -v -tags 'cloud_integration awscompute' \
		-count=1 -timeout 20m ./pkg/compute/aws -run TestAWSCompute_RealCloud

## test-cloud-compute-gcp: Run GCP Shielded VM live cloud tests (opt-in; needs GCP credentials and COMPUTE_GCP_*)
.PHONY: test-cloud-compute-gcp
test-cloud-compute-gcp:
	@echo "$(CYAN)→ Running GCP Shielded VM compute cloud tests (real GCP, may incur cost)$(RESET)"
	COMPUTE_GCP_LIVE=1 $(GOBIN)/go test -v -tags 'cloud_integration gcpcompute' \
		-count=1 -timeout 20m ./pkg/compute/gcp -run TestGCPCompute_RealCloud

## test-cloud-compute-azure: Run Azure Trusted Launch live cloud tests (opt-in; needs Azure credentials and COMPUTE_AZURE_*)
.PHONY: test-cloud-compute-azure
test-cloud-compute-azure:
	@echo "$(CYAN)→ Running Azure Trusted Launch compute cloud tests (real Azure, may incur cost)$(RESET)"
	COMPUTE_AZURE_LIVE=1 $(GOBIN)/go test -v -tags 'cloud_integration azurecompute' \
		-count=1 -timeout 25m ./pkg/compute/azure -run TestAzureCompute_RealCloud

## integration-test-compute-aws: Run the AWS EC2 lifecycle test against the Floci emulator (no cloud credentials)
.PHONY: integration-test-compute-aws
integration-test-compute-aws:
	@echo "$(CYAN)$(BOLD)→ Running AWS EC2 lifecycle integration test against Floci emulator...$(RESET)"
	@cd test/integration/compute-aws && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/compute-aws && docker compose up -d --wait floci
	@FLOCI_EC2_ENDPOINT=http://localhost:4566 $(GOBIN)/go test -v \
		-tags 'floci_integration awscompute $(INTEGRATION_CODEC_TAGS)' \
		-count=1 -timeout 15m ./pkg/compute/aws -run TestAWSCompute_Floci; \
		EXIT_CODE=$$?; \
		cd test/integration/compute-aws && docker compose down -v >/dev/null 2>&1 || true; \
		exit $$EXIT_CODE
	@echo "$(GREEN)✓ AWS EC2 Floci lifecycle test complete$(RESET)"

## integration-test-compute-aws-real: Run the AWS EC2 NitroTPM live-cloud test against real AWS, including EK attestation (credentials required)
.PHONY: integration-test-compute-aws-real
integration-test-compute-aws-real:
	@echo "$(CYAN)$(BOLD)→ Running AWS EC2 NitroTPM live-cloud test (REAL AWS, provisions BILLABLE resources)...$(RESET)"
	COMPUTE_AWS_LIVE=1 $(GOBIN)/go test -v \
		-tags 'cloud_integration awscompute $(INTEGRATION_CODEC_TAGS)' \
		-count=1 -timeout 20m ./pkg/compute/aws -run TestAWSCompute_RealCloud
	@echo "$(GREEN)✓ AWS EC2 NitroTPM live-cloud test complete$(RESET)"

## integration-test-compute-gcp-real: Run the GCP Shielded VM live-cloud test against real GCP, including vTPM attestation (credentials required)
.PHONY: integration-test-compute-gcp-real
integration-test-compute-gcp-real:
	@echo "$(CYAN)$(BOLD)→ Running GCP Shielded VM live-cloud test (REAL GCP, provisions BILLABLE resources)...$(RESET)"
	COMPUTE_GCP_LIVE=1 $(GOBIN)/go test -v \
		-tags 'cloud_integration gcpcompute $(INTEGRATION_CODEC_TAGS)' \
		-count=1 -timeout 20m ./pkg/compute/gcp -run TestGCPCompute_RealCloud
	@echo "$(GREEN)✓ GCP Shielded VM live-cloud test complete$(RESET)"

## integration-test-compute-azure-real: Run the Azure Trusted Launch live-cloud test against real Azure, including vTPM attestation (credentials required)
.PHONY: integration-test-compute-azure-real
integration-test-compute-azure-real:
	@echo "$(CYAN)$(BOLD)→ Running Azure Trusted Launch live-cloud test (REAL Azure, provisions BILLABLE resources)...$(RESET)"
	COMPUTE_AZURE_LIVE=1 $(GOBIN)/go test -v \
		-tags 'cloud_integration azurecompute $(INTEGRATION_CODEC_TAGS)' \
		-count=1 -timeout 25m ./pkg/compute/azure -run TestAzureCompute_RealCloud
	@echo "$(GREEN)✓ Azure Trusted Launch live-cloud test complete$(RESET)"

## integration-test-compute-cloud-real: Run all three real-cloud compute tests
.PHONY: integration-test-compute-cloud-real
integration-test-compute-cloud-real: integration-test-compute-aws-real integration-test-compute-gcp-real integration-test-compute-azure-real
	@echo "$(GREEN)✓ All real-cloud compute tests complete (AWS + GCP + Azure)$(RESET)"

## integration-test-attestation: Run attestation multi-protocol integration tests in devcontainer
.PHONY: integration-test-attestation
integration-test-attestation: build-devcontainer
	$(call run-integration-suite,attestation)

## integration-test-device: Run Device multi-protocol integration tests in devcontainer
.PHONY: integration-test-device
integration-test-device: build-devcontainer
	$(call run-integration-suite,device)

## integration-test-provision: Run config-delivery provisioning multi-protocol integration tests in devcontainer
.PHONY: integration-test-provision
integration-test-provision: build-devcontainer
	$(call run-integration-suite,provision)

## integration-test-secureboot: Run Secure Boot integration tests (OVMF enforce cycle, module signing, FIPS-kernel insmod rejection) in devcontainer
.PHONY: integration-test-secureboot
integration-test-secureboot: build-devcontainer
	@echo "NOTE: the FIPS-kernel insmod test requires FIPS_KERNEL_IMAGE, FIPS_MODULES_TAR and FIPS_MODULE_SIGNING_KEY (see docs/firmware/secure-boot.md)"
	$(call run-integration-suite,secureboot)

## integration-test-secureboot-hw: Run the real-hardware Secure Boot tier on the target node (host TPM quote and read-only efivarfs checks)
.PHONY: integration-test-secureboot-hw
integration-test-secureboot-hw:
	@echo "Running Secure Boot HARDWARE integration tier..."
	@echo "NOTE: run this ON the target node (e.g. Supermicro X10) with a provisioned hardware TPM,"
	@echo "      NOT in the devcontainer. The efivars checks are strictly read-only; the efivars"
	@echo "      WRITE path is validated via 'platformctl secure-boot enroll' (dry-run, then --commit)."
	TP_HW_TPM=1 TP_HW_EFIVARS=1 TP_HW_TPM_DEVICE=$(TP_HW_TPM_DEVICE) 		go test $(TEST_BUILD_TAGS_ARG) -count=1 -v 		-run 'TestHardware' ./test/integration/secureboot/hardware/...

## integration-test-cold-start: Run cold-start lifecycle integration tests in devcontainer
.PHONY: integration-test-cold-start
integration-test-cold-start: build-devcontainer
	$(call run-integration-suite,cold-start)

## integration-test-barrier-gate: Run M6 barrier-gate (init-only loopback) integration tests in devcontainer
.PHONY: integration-test-barrier-gate
integration-test-barrier-gate: build-devcontainer
	$(call run-integration-suite,barrier-gate)

## integration-test-tpm: Run TPM multi-protocol integration tests in devcontainer
.PHONY: integration-test-tpm
integration-test-tpm: build-devcontainer
	$(call run-integration-suite,tpm)

## integration-test-bootstrap: Run bootstrap orchestrator integration tests in devcontainer
.PHONY: integration-test-bootstrap
integration-test-bootstrap: build-devcontainer
	$(call run-integration-suite,bootstrap)

# NTP tests
NTP_TAGS := iam rest quic mcp cluster codec_json codec_msgpack codec_cbor

## test-ntp: Run time-synchronization unit tests across every transport
.PHONY: test-ntp
test-ntp:
	@echo "Running NTP (time synchronization) unit tests..."
	go test -count=1 -timeout 120s -tags '$(NTP_TAGS)' \
		./pkg/ntp/... \
		./pkg/cli/commands/ntp/... \
		./pkg/webservice/v1/rest/ntp/...
	go test -count=1 -timeout 120s -tags '$(NTP_TAGS)' -run 'NTP' \
		./pkg/app/... \
		./pkg/api/daemon/... \
		./pkg/api/rest/... \
		./pkg/api/mcp/...
	cd sdk/go && go test -count=1 -timeout 120s -tags '$(NTP_TAGS)' ./services/ntp/... && \
		go test -count=1 -timeout 120s -tags '$(NTP_TAGS)' -run 'NTP' ./transport/...

## coverage-ntp: Time-synchronization coverage report
.PHONY: coverage-ntp
coverage-ntp:
	@mkdir -p build/coverage
	go test -count=1 -timeout 120s -tags '$(NTP_TAGS)' \
		-coverprofile=/tmp/ntp.cover \
		./pkg/ntp/... ./pkg/cli/commands/ntp/... ./pkg/webservice/v1/rest/ntp/...
	go tool cover -func=/tmp/ntp.cover | tail -1
	@go tool cover -html=/tmp/ntp.cover -o build/coverage/ntp.html
	@echo "Coverage report: build/coverage/ntp.html"

## integration-test-ntp: Run NTP multi-protocol integration tests in devcontainer
.PHONY: integration-test-ntp
integration-test-ntp: build-devcontainer
	$(call run-integration-suite,ntp)

## integration-test-objectstorage: Run object storage multi-protocol integration tests in devcontainer
.PHONY: integration-test-objectstorage
integration-test-objectstorage: build-devcontainer
	$(call run-integration-suite,objectstorage)

# VPN (management-VPN control plane) tests

## test-vpn: Run management-VPN unit tests across every transport
.PHONY: test-vpn
test-vpn:
	@echo "Running VPN control-plane unit tests..."
	go test -count=1 -timeout 120s -tags '$(BUILD_TAGS)' \
		./pkg/vpn/... \
		./pkg/cli/commands/vpn/... \
		./pkg/webservice/v1/rest/vpn/...
	go test -count=1 -timeout 120s -tags '$(BUILD_TAGS)' -run 'VPN' \
		./pkg/api/daemon/... \
		./pkg/api/rest/... \
		./pkg/api/mcp/...
	cd sdk/go && go test -count=1 -timeout 120s -tags '$(BUILD_TAGS)' ./services/vpn/... && \
		go test -count=1 -timeout 120s -tags '$(BUILD_TAGS)' -run 'VPN' ./transport/...

## coverage-vpn: Management-VPN coverage report
.PHONY: coverage-vpn
coverage-vpn:
	@mkdir -p build/coverage
	go test -count=1 -timeout 120s -tags '$(BUILD_TAGS)' \
		-coverprofile=/tmp/vpn.cover \
		./pkg/vpn/... ./pkg/cli/commands/vpn/... ./pkg/webservice/v1/rest/vpn/...
	go tool cover -func=/tmp/vpn.cover | tail -1
	@go tool cover -html=/tmp/vpn.cover -o build/coverage/vpn.html
	@echo "Coverage report: build/coverage/vpn.html"

## bench-vpn: Benchmark the VPN desired-config render and the gateway's enrolment apply
.PHONY: bench-vpn
bench-vpn:
	go test -tags '$(BUILD_TAGS)' -bench=. -benchmem -run=^$$ \
		./pkg/vpn/... \
		./pkg/sdn/gateway/services/vpn/...

## integration-test-vpn: Run VPN multi-protocol integration tests in devcontainer
.PHONY: integration-test-vpn
integration-test-vpn: build-devcontainer
	$(call run-integration-suite,vpn)

## integration-test-installer: Run the installer suite (real dnsmasq forwards the internal zone) in devcontainer
.PHONY: integration-test-installer
integration-test-installer: build-devcontainer
	$(call run-integration-suite,installer)

## integration-test-root: Run the root package (test/integration, not its subdirectories) in devcontainer
.PHONY: integration-test-root
integration-test-root: build-devcontainer
	$(call run-integration-suite,root)

## integration-test-helpers: Run the integration-tagged tests of the shared harness library in devcontainer
.PHONY: integration-test-helpers
integration-test-helpers: build-devcontainer
	$(call run-integration-suite,helpers)

## integration-test-acme: Run the ACME suite (test/integration/acme) in devcontainer
.PHONY: integration-test-acme
integration-test-acme: build-devcontainer
	$(call run-integration-suite,acme)

## integration-test-authenticode: Run the Authenticode suite (test/integration/authenticode) in devcontainer
.PHONY: integration-test-authenticode
integration-test-authenticode: build-devcontainer
	$(call run-integration-suite,authenticode)

## integration-test-cli: Run the platformctl suite (test/integration/cli) in devcontainer
.PHONY: integration-test-cli
integration-test-cli: build-devcontainer
	$(call run-integration-suite,cli)

## integration-test-compute: Run the compute VM multi-protocol suite (test/integration/compute) in devcontainer, platformd on local-qemu
.PHONY: integration-test-compute
integration-test-compute: build-devcontainer
	$(call run-integration-suite,compute)

## integration-test-container: Run the container suite (test/integration/container) in devcontainer
.PHONY: integration-test-container
integration-test-container: build-devcontainer
	$(call run-integration-suite,container)

## integration-test-iso: Run the ISO suite (test/integration/iso) in devcontainer
.PHONY: integration-test-iso
integration-test-iso: build-devcontainer
	$(call run-integration-suite,iso)

## integration-test-pxe: Run the PXE suite (test/integration/pxe) in devcontainer
.PHONY: integration-test-pxe
integration-test-pxe: build-devcontainer
	$(call run-integration-suite,pxe)

## integration-test-registry: Run the registry suite (test/integration/registry) in devcontainer
.PHONY: integration-test-registry
integration-test-registry: build-devcontainer
	$(call run-integration-suite,registry)

## bench-ntp: Run time-synchronization benchmarks
.PHONY: bench-ntp
bench-ntp:
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/ntp/...

## bench-bmc: Run BMC benchmarks
.PHONY: bench-bmc
bench-bmc:
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/bmc/...

.PHONY: test-webservice
test-webservice: test-webservice-jwt

.PHONY: test-webservice-jwt
test-webservice-jwt:
	cd pkg/webservice/v1/jwt && \
		go test -tags "pkcs11 objstore" -v -run ^TestSigningMethodRS$ && \
		go test -tags "pkcs11 objstore" -v -run ^TestSigningMethodPS$ && \
		go test -tags "pkcs11 objstore" -v -run ^TestSigningMethodES$ && \
		go test -tags "pkcs11 objstore" -v -run ^TestSigningMethodES_Ed25519$


# Integration tests: docker containers with real services, end to end.

# In-container root the source repositories are mounted under.
SOURCES_BASE := /sources

# Sibling-module bind mounts, empty: modules resolve from tags.
DOCKER_MODULE_MOUNTS :=

# The host module cache, mounted into the devcontainer.
GO_MODULE_CACHE := $(if $(GO_CMD),$(shell go env GOMODCACHE),$(or $(GOMODCACHE),$(if $(GOPATH),$(firstword $(subst :, ,$(GOPATH)))/pkg/mod),$(HOME)/go/pkg/mod))

# One devcontainer invocation for every per-package integration suite.
define run-integration-suite
	@echo "Running $(1) integration tests in the development container..."
	@echo "Build tags: $(TEST_BUILD_TAGS)"
	@docker run --rm --privileged \
		--name go-trusted-platform-$(1)-test \
		--memory $(IT_MEMORY) --memory-swap $(IT_MEMORY) \
		$(if $(CI_CGROUP_PARENT),--cgroup-parent $(CI_CGROUP_PARENT)) \
		--device /dev/net/tun:/dev/net/tun \
		--tmpfs /tmp:exec,mode=1777 \
		-v $(PWD):$(SOURCES_BASE)/go-trusted-platform \
		-v $(PWD):/workspace \
		-v $(GO_MODULE_CACHE):/go/pkg/mod \
		$(DOCKER_MODULE_MOUNTS) \
		-w $(SOURCES_BASE)/go-trusted-platform \
		-e CGO_ENABLED=1 \
		-e GOTOOLCHAIN=auto \
		-e GOWORK=off \
		-e HOST_UID=$(shell id -u) \
		-e HOST_GID=$(shell id -g) \
		$(2) \
		$(DEVCONTAINER_IMAGE) \
		bash /workspace/build/docker/devcontainer/run-integration-tests.sh $(1) "$(strip $(TEST_BUILD_TAGS))"
endef

.PHONY: integration-test
## integration-test: Run all integration suites in the integration image
integration-test: SHELL := /bin/bash
integration-test: $(if $(IT_PREBUILT),,docker-build-it)
	@echo "Build tags: $(TEST_BUILD_TAGS)"
	@set -o pipefail; status=0; \
	export GO_TRUSTED_PLATFORM_IT_IMAGE=$(IT_IMAGE) GO_TRUSTED_PLATFORM_IT_MEMORY=$(IT_MEMORY) CI_CGROUP_PARENT='$(CI_CGROUP_PARENT)'; \
	teardown() { \
		docker compose -f $(DEVCONTAINER_COMPOSE) -p $(IT_PROJECT) down --volumes --remove-orphans || \
			echo "warning: teardown of $(IT_PROJECT) failed; scripts/reap-stale-ci-stacks.sh removes what is left" >&2; \
	}; \
	trap teardown EXIT; trap 'exit 130' INT; trap 'exit 143' TERM; \
	docker volume create go-trusted-platform-iso-apk-cache >/dev/null; \
	HOST_UID=$$(id -u) HOST_GID=$$(id -g) \
		docker compose -f $(DEVCONTAINER_COMPOSE) -p $(IT_PROJECT) \
		run --rm integration $(IT_SELECT) "$(strip $(TEST_BUILD_TAGS))" $(if $(IT_FOREIGN_BASELINE),2>&1 | tee "$(IT_LOG)") || status=$$?; \
	if [ $$status -ne 0 ] && [ -n "$(IT_FOREIGN_BASELINE)" ]; then \
		echo "Integration suites failed (status $$status); checking the failures against $(FOREIGN_BASELINE) (ruling 125)"; \
		status=0; \
		$(GO) run ./scripts/foreignfailures -job integration -baseline $(FOREIGN_BASELINE) "$(IT_LOG)" || status=$$?; \
	fi; \
	exit $$status

.PHONY: integration-test-leg
## integration-test-leg: Run one leg of the integration suite (LEG=<n>), as CI does
integration-test-leg: IT_SELECT = leg-$(LEG)
integration-test-leg: integration-test
ifneq ($(filter integration-test-leg,$(MAKECMDGOALS)),)
ifeq ($(strip $(LEG)),)
$(error integration-test-leg needs LEG=<n>, a leg of INTEGRATION_LEGS in the suite runner; docs/test/integration.md lists them)
endif
endif

.PHONY: integration-test-webservice
integration-test-webservice: docker-builder-load
	@echo "Running webservice integration tests in docker container..."
	docker run --rm --privileged \
		-v $(PWD):/workspace \
		$(DOCKER_MODULE_MOUNTS) \
		-w /workspace \
		$(APPNAME)-builder-$(DOCKER_BUILDER_BASE):amd64 \
		/bin/sh -c "CGO_ENABLED=1 go test -tags 'pkcs11 objstore integration' -v ./pkg/webservice/v1/test/..."

# SDN Integration Tests (using devcontainer)
.PHONY: integration-test-sdn
## integration-test-sdn: Run SDN integration tests in the development container
integration-test-sdn: build-devcontainer
	$(call run-integration-suite,sdn)

.PHONY: integration-test-sdn-stress
## integration-test-sdn-stress: Run the SDN stress generators in the development container, apart from integration-test-sdn
integration-test-sdn-stress: build-devcontainer
	$(call run-integration-suite,sdn-stress)

.PHONY: integration-test-sdn-shell
## integration-test-sdn-shell: Start interactive shell for SDN testing
integration-test-sdn-shell: build-devcontainer
	@echo "Starting SDN test shell..."
	@docker run --rm -it --privileged \
		--name go-trusted-platform-sdn-shell \
		--device /dev/net/tun:/dev/net/tun \
		-v $(PWD):/workspace \
		$(DOCKER_MODULE_MOUNTS) \
		-w /workspace \
		$(DEVCONTAINER_IMAGE) \
		bash

# KMS Integration Tests (with TPM simulator)
.PHONY: integration-test-kms
## integration-test-kms: Run KMS integration tests in the devcontainer
integration-test-kms: build-devcontainer
	$(call run-integration-suite,kms)

.PHONY: integration-test-kms-local
## integration-test-kms-local: Run KMS integration tests locally (requires swtpm installed)
integration-test-kms-local:
	@echo "Running KMS integration tests locally..."
	@if ! command -v swtpm > /dev/null 2>&1; then \
		echo "ERROR: swtpm not installed. Install with: apt-get install swtpm swtpm-tools"; \
		exit 1; \
	fi
	go test -v $(TEST_BUILD_TAGS_ARG) -count=1 -timeout=10m ./test/integration/kms/...

# Secrets Integration Tests (with TPM simulator)
.PHONY: integration-test-secrets
## integration-test-secrets: Run Secrets integration tests in the devcontainer
integration-test-secrets: build-devcontainer
	$(call run-integration-suite,secrets)

.PHONY: integration-test-secrets-local
## integration-test-secrets-local: Run Secrets integration tests locally (requires swtpm installed)
integration-test-secrets-local:
	@echo "Running Secrets integration tests locally..."
	@if ! command -v swtpm > /dev/null 2>&1; then \
		echo "ERROR: swtpm not installed. Install with: apt-get install swtpm swtpm-tools"; \
		exit 1; \
	fi
	go test -v $(TEST_BUILD_TAGS_ARG) -count=1 -timeout=10m ./test/integration/secrets/...

# Development container
include scripts/tool-pins.sh

DEVCONTAINER_DOCKERFILE := build/docker/devcontainer/Dockerfile
DEVCONTAINER_COMPOSE := build/docker/devcontainer/compose.yaml
DEVCONTAINER_IMAGE := trusted-platform-dev:latest
DEVCONTAINER_NAME := trusted-platform-devcontainer

# DEVCONTAINER_WAIT_FOR loads the harness's bounded readiness polls into a `docker exec` script.
DEVCONTAINER_WAIT_FOR := source /workspace/build/docker/devcontainer/wait-for.sh

# The toolchain image tag hashes everything baked into it.
TOOLCHAIN_INPUTS := $(DEVCONTAINER_DOCKERFILE) scripts/tool-pins.sh \
	go.mod go.sum sdk/go/go.mod sdk/go/go.sum \
	$(wildcard build/tools-src/*/go.mod build/tools-src/*/go.sum)
TOOLCHAIN_TAG = $(shell cat $(TOOLCHAIN_INPUTS) | sha256sum | cut -c1-16)
TOOLCHAIN_IMAGE = go-trusted-platform-toolchain:$(TOOLCHAIN_TAG)

# The integration image and the compose project `make integration-test` uses.
IT_IMAGE ?= go-trusted-platform-it:local
IT_PROJECT ?= go-trusted-platform-it
# Set to use an $(IT_IMAGE) that is already built (integration-test).
IT_PREBUILT ?=

# The integration container's memory limit, swap included.
IT_MEMORY ?= 16g

# The cgroup parent of every container CI starts.
CI_CGROUP_PARENT ?= ci.slice

# The foreign-failure baseline.
IT_FOREIGN_BASELINE ?=
IT_LOG ?= $(or $(TMPDIR),/tmp)/go-trusted-platform-integration.log
FOREIGN_BASELINE ?= .github/foreign-failures.tsv
# `all`, or `leg-<n>` when integration-test-leg runs it.
IT_SELECT := all
# The FIPS job's sibling baseline, always consulted by `make test-fips`.
FIPS_LOG ?= $(or $(TMPDIR),/tmp)/go-trusted-platform-fips.log
FIPS_FOREIGN_BASELINE ?= .github/foreign-failures-fips.tsv

# A KEY=value file with the forge credentials the module download needs.
MODULE_ENV_FILE ?= .devcontainer/.env

# The docker build arguments every devcontainer stage shares.
APT_REFRESH ?= $(eval APT_REFRESH := $$(shell scripts/apt-refresh-key.sh))$(APT_REFRESH)

# The Alpine package index checksum (scripts/apk-index-sum.sh).
APK_INDEX_SUM ?=

# GO_BUILD_PROXY is passed only when set, and quoted, because CI's value uses the | separator.
DEVCONTAINER_BUILD_ARGS = --build-arg GO_IMAGE=$(GO_IMAGE) \
	--build-arg APT_REFRESH=$(APT_REFRESH) \
	$(if $(GO_BUILD_PROXY),--build-arg "GO_BUILD_PROXY=$(GO_BUILD_PROXY)") \
	$(if $(wildcard $(MODULE_ENV_FILE)),--secret id=gomodauth$(comma)src=$(MODULE_ENV_FILE)) \
	-f $(DEVCONTAINER_DOCKERFILE)

# The BuildKit builder the devcontainer images build on.
BUILDX_BUILDER ?=
# BUILDX_CLIENT_LOAD=1 streams the image to this shell's `docker load` instead of --load.
BUILDX_CLIENT_LOAD ?=
DEVCONTAINER_CLIENT_LOAD = $(and $(BUILDX_BUILDER),$(BUILDX_CLIENT_LOAD))
DEVCONTAINER_BUILD = $(if $(BUILDX_BUILDER),docker buildx build --builder $(BUILDX_BUILDER) $(if $(DEVCONTAINER_CLIENT_LOAD),--output type=docker$(comma)dest=-,--load),DOCKER_BUILDKIT=1 docker build)

.PHONY: docker-build docker-build-integration docker-build-toolchain
## docker-build: Build the integration image and the toolchain image
docker-build: docker-build-integration docker-build-toolchain

## docker-build-integration: Build the integration image as $(IT_IMAGE), without the warm build cache
docker-build-integration:
	$(DEVCONTAINER_BUILD) $(DEVCONTAINER_BUILD_ARGS) --build-arg APK_INDEX_SUM=$(APK_INDEX_SUM) \
		--target integration -t $(IT_IMAGE) .

## docker-build-toolchain: Build the toolchain image as $(TOOLCHAIN_IMAGE)
docker-build-toolchain:
	$(DEVCONTAINER_BUILD) $(DEVCONTAINER_BUILD_ARGS) --target toolchain -t $(TOOLCHAIN_IMAGE) .

# IT_WARM_CACHE=0 skips the warm build cache.
IT_WARM_CACHE ?= 1
IT_BUILD_TARGET = $(if $(filter 0,$(IT_WARM_CACHE)),integration,integration-legs)

.PHONY: docker-build-it
## docker-build-it: Build the image the integration suites run in as $(IT_IMAGE), with a warm build cache
docker-build-it: SHELL := /bin/bash
docker-build-it:
	$(if $(DEVCONTAINER_CLIENT_LOAD),set -o pipefail; )$(DEVCONTAINER_BUILD) $(DEVCONTAINER_BUILD_ARGS) --build-arg APK_INDEX_SUM=$(APK_INDEX_SUM) \
		--target $(IT_BUILD_TARGET) 		--build-arg IT_BUILD_TAGS="$(strip $(TEST_BUILD_TAGS))" -t $(IT_IMAGE) . $(if $(DEVCONTAINER_CLIENT_LOAD),| docker load)

# The integration image's content tag: a hash of the build arguments and the build context.
IT_IMAGE_REPO := go-trusted-platform-ci-it

.PHONY: it-image
## it-image: Print the integration image's content tag, $(IT_IMAGE_REPO):<hash>
it-image: SHELL := /bin/bash
it-image:
	@set -euo pipefail; \
	{ printf '%s\n' 'GO_IMAGE=$(GO_IMAGE)' 'APT_REFRESH=$(APT_REFRESH)' 'APK_INDEX_SUM=$(APK_INDEX_SUM)' \
		'TARGET=$(IT_BUILD_TARGET)' 'IT_BUILD_TAGS=$(if $(filter integration-legs,$(IT_BUILD_TARGET)),$(strip $(TEST_BUILD_TAGS)))'; \
	  git rev-parse 'HEAD^{tree}'; \
	  git diff --binary HEAD; \
	  git ls-files -z --others --exclude-standard | xargs -0r sha256sum --; \
	} | sha256sum | cut -c1-16 | sed 's|^|$(IT_IMAGE_REPO):|'

.PHONY: toolchain-image
## toolchain-image: Print the toolchain image tag (CI reads it with make -s)
toolchain-image:
	@echo $(TOOLCHAIN_IMAGE)

.PHONY: docker-run
## docker-run: Run CMD in the toolchain image with the checkout mounted (CMD='make lint')
docker-run:
	@test -n "$(CMD)" || { echo "usage: make docker-run CMD='make lint'" >&2; exit 2; }
	GO_TRUSTED_PLATFORM_TOOLCHAIN_TAG=$(TOOLCHAIN_TAG) \
	GO_TRUSTED_PLATFORM_UID=$$(id -u) GO_TRUSTED_PLATFORM_GID=$$(id -g) \
		docker compose -f $(DEVCONTAINER_COMPOSE) run --rm toolchain sh -c '$(CMD)'

.PHONY: build-devcontainer
## build-devcontainer: Build the interactive development container (the integration stage)
build-devcontainer:
	@echo "Building development container..."
	DOCKER_BUILDKIT=1 docker build $(DEVCONTAINER_BUILD_ARGS) --target integration -t $(DEVCONTAINER_IMAGE) .

.PHONY: devcontainer-shell
## devcontainer-shell: Start an interactive shell in the development container
devcontainer-shell: build-devcontainer
	@echo "Starting development container shell..."
	@docker run --rm -it --privileged \
		--name trusted-platform-shell \
		-v $(PWD):/workspace \
		$(DOCKER_MODULE_MOUNTS) \
		-w /workspace \
		$(DEVCONTAINER_IMAGE) \
		bash

.PHONY: devcontainer-verify
## devcontainer-verify: Verify development container tooling
devcontainer-verify: build-devcontainer
	@docker run --rm $(DEVCONTAINER_IMAGE) verify


# SDN benchmark tests

.PHONY: bench-sdn
## bench-sdn: Run all SDN package benchmarks
bench-sdn:
	@echo "$(CYAN)Running SDN benchmarks...$(RESET)"
	@echo "$(CYAN)→ VXLAN benchmarks$(RESET)"
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/sdn/vxlan/...
	@echo "$(CYAN)→ BGP benchmarks$(RESET)"
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/sdn/bgp/...
	@echo "$(CYAN)→ Gateway benchmarks$(RESET)"
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/sdn/gateway/...
	@echo "$(CYAN)→ IPAM benchmarks$(RESET)"
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/sdn/ipam/...
	@echo "$(CYAN)→ Overlay benchmarks$(RESET)"
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/sdn/overlay/...
	@echo "$(CYAN)→ DHCP benchmarks$(RESET)"
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/sdn/dhcp/...
	@echo "$(CYAN)→ OpenFlow benchmarks$(RESET)"
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/sdn/openflow/...
	@echo "$(GREEN)SDN benchmarks complete$(RESET)"

.PHONY: bench-sdn-vxlan
## bench-sdn-vxlan: Run VXLAN package benchmarks
bench-sdn-vxlan:
	@echo "$(CYAN)Running VXLAN benchmarks...$(RESET)"
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/sdn/vxlan/...

.PHONY: bench-sdn-bgp
## bench-sdn-bgp: Run BGP package benchmarks
bench-sdn-bgp:
	@echo "$(CYAN)Running BGP benchmarks...$(RESET)"
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/sdn/bgp/...

.PHONY: bench-sdn-gateway
## bench-sdn-gateway: Run Gateway package benchmarks
bench-sdn-gateway:
	@echo "$(CYAN)Running Gateway benchmarks...$(RESET)"
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/sdn/gateway/...

.PHONY: bench-sdn-ipam
## bench-sdn-ipam: Run IPAM package benchmarks
bench-sdn-ipam:
	@echo "$(CYAN)Running IPAM benchmarks...$(RESET)"
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/sdn/ipam/...

.PHONY: bench-sdn-overlay
## bench-sdn-overlay: Run overlay package benchmarks
bench-sdn-overlay:
	@echo "$(CYAN)Running overlay benchmarks...$(RESET)"
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/sdn/overlay/...

.PHONY: bench-sdn-dhcp
## bench-sdn-dhcp: Run DHCP package benchmarks
bench-sdn-dhcp:
	@echo "$(CYAN)Running DHCP benchmarks...$(RESET)"
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/sdn/dhcp/...

.PHONY: bench-sdn-openflow
## bench-sdn-openflow: Run OpenFlow package benchmarks
bench-sdn-openflow:
	@echo "$(CYAN)Running OpenFlow benchmarks...$(RESET)"
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/sdn/openflow/...

# SDN, OVS and QEMU integration tests

.PHONY: integration-test-sdn-full
## integration-test-sdn-full: Run full SDN tests with OVS in privileged devcontainer
integration-test-sdn-full: build-devcontainer
	@echo "Running full SDN integration tests with OVS..."
	@docker run --rm --privileged \
		--name go-trusted-platform-sdn-full \
		--device /dev/net/tun:/dev/net/tun \
		--cap-add=NET_ADMIN \
		--cap-add=SYS_MODULE \
		-e AUTO_START_OVS=true \
		-e CGO_ENABLED=0 \
		-v $(PWD):/workspace \
		$(DOCKER_MODULE_MOUNTS) \
		-w /workspace \
		$(DEVCONTAINER_IMAGE) \
		go test -v $(TEST_BUILD_TAGS_ARG) -count=1 -parallel 1 -timeout 15m ./test/integration/sdn/...

.PHONY: integration-test-sdn-topology
## integration-test-sdn-topology: Run the multi-node SDN topology suite on a host with docker-compose
integration-test-sdn-topology:
	go test -v -tags '$(strip $(TEST_BUILD_TAGS)) topology' -count=1 -timeout 30m ./test/integration/sdn/topology/

.PHONY: integration-test-lb
## integration-test-lb: Run the gateway load balancer datapath test in the devcontainer
integration-test-lb: build-devcontainer
	$(call run-integration-suite,lb)

.PHONY: integration-test-e2e
## integration-test-e2e: Run end-to-end tests with QEMU VMs and OVS networking; without the ISO variables it validates the infrastructure only
integration-test-e2e: build-devcontainer
	$(call run-integration-suite,e2e,-e INTEGRATION_TEST_SERVER_ISO -e INTEGRATION_TEST_CLIENT_ISO)

.PHONY: integration-test-device-profile
## integration-test-device-profile: Test device profile network state transitions
integration-test-device-profile: build-devcontainer
	@echo "Running device profile network transition tests..."
	@docker run --rm --privileged \
		--name trusted-platform-device-profile \
		--device /dev/net/tun:/dev/net/tun \
		--cap-add=NET_ADMIN \
		--cap-add=SYS_MODULE \
		-e AUTO_START_OVS=true \
		-e CGO_ENABLED=0 \
		-v $(PWD):/workspace \
		$(DOCKER_MODULE_MOUNTS) \
		-w /workspace \
		$(DEVCONTAINER_IMAGE) \
		go test -v $(TEST_BUILD_TAGS_ARG) -timeout=20m -run TestDeviceProfile ./test/integration/sdn/...


.PHONY: stress-sdn
## stress-sdn: Run SDN stress tests in development container
stress-sdn: build-devcontainer
	@echo "Running SDN stress tests in development container..."
	@docker run --rm --privileged \
		--name go-trusted-platform-sdn-stress \
		--device /dev/net/tun:/dev/net/tun \
		--cap-add=NET_ADMIN \
		--cap-add=SYS_MODULE \
		-e AUTO_START_OVS=true \
		-e CGO_ENABLED=0 \
		-v $(PWD):/workspace \
		$(DOCKER_MODULE_MOUNTS) \
		-w /workspace/test/integration/sdn \
		$(DEVCONTAINER_IMAGE) \
		go test -v $(TEST_BUILD_TAGS_ARG) -timeout=30m ./stress/...

.PHONY: stress-sdn-cluster
## stress-sdn-cluster: Run cluster state stress tests
stress-sdn-cluster: build-devcontainer
	@echo "Running cluster state stress tests..."
	@docker run --rm --privileged \
		--name go-trusted-platform-cluster-stress \
		-e CGO_ENABLED=0 \
		-v $(PWD):/workspace \
		$(DOCKER_MODULE_MOUNTS) \
		-w /workspace/test/integration/sdn \
		$(DEVCONTAINER_IMAGE) \
		go test -v $(TEST_BUILD_TAGS_ARG) -timeout=15m -run TestCluster ./stress/...

.PHONY: stress-sdn-local
## stress-sdn-local: Run SDN stress tests locally (without container)
stress-sdn-local:
	@echo "Running SDN stress tests locally..."
	cd test/integration/sdn && go test -v $(TEST_BUILD_TAGS_ARG) -timeout=30m ./stress/...

# Docker Compose based integration tests

.PHONY: devcontainer-compose-up
## devcontainer-compose-up: Start all integration test services via docker-compose
devcontainer-compose-up: build-devcontainer
	@echo "Starting integration test environment with docker-compose..."
	@echo "Waiting for services to be running (healthy, where a healthcheck is defined)..."
	@cd build/docker/devcontainer && docker compose up -d --wait --wait-timeout 120
	@cd build/docker/devcontainer && docker compose ps

.PHONY: devcontainer-compose-down
## devcontainer-compose-down: Stop all integration test services
devcontainer-compose-down:
	@echo "Stopping integration test environment..."
	@cd build/docker/devcontainer && docker compose down -v

.PHONY: devcontainer-compose-logs
## devcontainer-compose-logs: View logs from integration test services
devcontainer-compose-logs:
	@cd build/docker/devcontainer && docker compose logs -f

.PHONY: devcontainer-compose-shell
## devcontainer-compose-shell: Connect to main devcontainer in compose environment
devcontainer-compose-shell: devcontainer-compose-up
	@echo "Connecting to devcontainer shell..."
	@docker exec -it $(DEVCONTAINER_NAME) bash

.PHONY: integration-test-compose-full
## integration-test-compose-full: Run full test suite using docker-compose environment
integration-test-compose-full: devcontainer-compose-up
	@echo "Running full integration test suite in compose environment..."
	@docker exec -e CGO_ENABLED=0 -w /workspace $(DEVCONTAINER_NAME) \
		go test -v $(TEST_BUILD_TAGS_ARG) -count=1 -parallel 1 -timeout 30m \
		./test/integration/sdn/... \
		./test/integration/vtpm/...
	@$(MAKE) devcontainer-compose-down

.PHONY: integration-test-web-shell
## integration-test-web-shell: Start shell with backend running for manual web testing
integration-test-web-shell: devcontainer-compose-up
	@echo "$(CYAN)Starting web testing environment...$(RESET)"
	@echo ""
	@echo "$(YELLOW)→ Building backend...$(RESET)"
	@docker exec $(DEVCONTAINER_NAME) bash -c "cd /workspace && make build-debug config"
	@echo ""
	@echo "$(YELLOW)→ Starting backend webservice in background...$(RESET)"
	@docker exec -d $(DEVCONTAINER_NAME) bash -c "\
		cd /workspace/pkg && \
		../bin/platformd-debug --config config.yaml --raw-so-pin 123456 --raw-pin 123456 --init serve > /tmp/platformd.log 2>&1"
	@docker exec $(DEVCONTAINER_NAME) bash -c "$(DEVCONTAINER_WAIT_FOR) && \
		wait_for 120 'platformd REST on https://localhost:8443' curl -sk -o /dev/null https://localhost:8443/" || \
		(docker exec $(DEVCONTAINER_NAME) tail -50 /tmp/platformd.log; exit 1)
	@echo ""
	@echo "$(YELLOW)→ Installing frontend dependencies...$(RESET)"
	@docker exec $(DEVCONTAINER_NAME) bash -c "\
		cd /workspace/web && \
		npm install --silent"
	@echo ""
	@echo "$(GREEN)═══════════════════════════════════════════════════════════════$(RESET)"
	@echo "$(GREEN)  Environment Ready!$(RESET)"
	@echo "$(GREEN)═══════════════════════════════════════════════════════════════$(RESET)"
	@echo ""
	@echo "  Backend running on: https://localhost:8443"
	@echo ""
	@echo "  To start frontend dev server:"
	@echo "    cd /workspace/web && npm run dev"
	@echo ""
	@echo "  Then open: http://localhost:3000/auth/webauthn"
	@echo ""
	@echo "  To run E2E tests:"
	@echo "    cd /workspace/web && npm run test:e2e"
	@echo ""
	@docker exec -it $(DEVCONTAINER_NAME) bash

# Development container with full capabilities

.PHONY: devcontainer-shell-full
## devcontainer-shell-full: Start devcontainer with all devices and capabilities
devcontainer-shell-full: build-devcontainer
	@echo "Starting fully-equipped development container..."
	@docker run --rm -it --privileged \
		--name trusted-platform-full \
		--device /dev/net/tun:/dev/net/tun \
		$$([ -e /dev/kvm ] && echo "--device /dev/kvm:/dev/kvm") \
		--cap-add=NET_ADMIN \
		--cap-add=NET_RAW \
		--cap-add=SYS_MODULE \
		--cap-add=SYS_ADMIN \
		--cap-add=IPC_LOCK \
		--shm-size=2g \
		-e AUTO_START_OVS=true \
		-v $(PWD):/workspace \
		$(DOCKER_MODULE_MOUNTS) \
		-w /workspace \
		$(DEVCONTAINER_IMAGE) \
		ovs-shell

.PHONY: devcontainer-help
## devcontainer-help: Show devcontainer usage information
devcontainer-help: build-devcontainer
	@docker run --rm $(DEVCONTAINER_IMAGE) help


# vTPM integration tests
.PHONY: integration-test-vtpm
## integration-test-vtpm: Run full E2E vTPM integration tests (ISO creation and QEMU boot)
integration-test-vtpm: build-devcontainer
	$(call run-integration-suite,vtpm)

.PHONY: integration-test-vtpm-shell
## integration-test-vtpm-shell: Start interactive shell for vTPM testing
integration-test-vtpm-shell: build-devcontainer
	@echo "Starting vTPM test shell..."
	@docker run --rm -it --privileged \
		--name go-trusted-platform-vtpm-shell \
		-v $(PWD):/workspace \
		$(DOCKER_MODULE_MOUNTS) \
		-w /workspace \
		$(DEVCONTAINER_IMAGE) \
		bash

.PHONY: integration-test-vtpm-local
## integration-test-vtpm-local: Run vTPM Go unit tests locally (requires swtpm installed)
integration-test-vtpm-local:
	@echo "Running vTPM unit tests locally..."
	@if ! command -v swtpm > /dev/null 2>&1; then \
		echo "ERROR: swtpm not installed. Install with: apt-get install swtpm swtpm-tools"; \
		exit 1; \
	fi
	CGO_ENABLED=1 go test -v $(TEST_BUILD_TAGS_ARG) -timeout=10m ./test/integration/vtpm/...

.PHONY: devcontainer-clean
## devcontainer-clean: Remove development container and legacy test images
devcontainer-clean:
	@echo "Cleaning development container and legacy test images..."
	@docker rmi -f $(DEVCONTAINER_IMAGE) 2>/dev/null || true
	@docker rmi -f go-trusted-platform-vtpm-test:latest 2>/dev/null || true
	@docker rmi -f go-trusted-platform-sdn-test:latest 2>/dev/null || true
	@docker rmi -f go-trusted-platform-datastore-integration-test:latest 2>/dev/null || true

# Daemon multi-protocol integration tests
.PHONY: integration-test-daemon
## integration-test-daemon: Run daemon multi-protocol integration tests in development container
integration-test-daemon: build-devcontainer
	$(call run-integration-suite,daemon)

.PHONY: integration-test-daemon-local
## integration-test-daemon-local: Run daemon integration tests locally (requires services running)
integration-test-daemon-local:
	@echo "Running daemon integration tests locally..."
	go test -v $(TEST_BUILD_TAGS_ARG) -count=1 -timeout=10m ./test/integration/daemon/...

# IAM multi-protocol integration tests
.PHONY: integration-test-iam
## integration-test-iam: Run IAM multi-protocol integration tests in devcontainer
integration-test-iam: build-devcontainer
	$(call run-integration-suite,iam)

.PHONY: integration-test-iam-local
## integration-test-iam-local: Run IAM integration tests locally (requires services running)
integration-test-iam-local:
	@echo "Running IAM integration tests locally..."
	go test -v $(TEST_BUILD_TAGS_ARG) -count=1 -timeout=10m ./test/integration/iam/...


# iPXE and PXE integration tests
.PHONY: integration-test-ipxe
## integration-test-ipxe: Run iPXE/PXE integration tests in development container
integration-test-ipxe: build-devcontainer
	$(call run-integration-suite,ipxe)

.PHONY: integration-test-ipxe-local
## integration-test-ipxe-local: Run iPXE integration tests locally (requires root: the DHCP client binds UDP 68)
integration-test-ipxe-local:
	@echo "Running iPXE integration tests locally..."
	IPXE_DHCP_ENABLED=1 go test -v $(TEST_BUILD_TAGS_ARG) -count=1 -timeout=10m ./test/integration/ipxe/...

.PHONY: integration-test-ipxe-dhcp
## integration-test-ipxe-dhcp: Run only the DHCP protocol tests
integration-test-ipxe-dhcp: build-devcontainer
	$(call run-integration-suite,ipxe-dhcp)

# vTPM Coverage
.PHONY: coverage-vtpm
## coverage-vtpm: Generate vTPM package coverage report
coverage-vtpm:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating vTPM coverage report...$(RESET)"
	@$(GOTEST) -tags "$(BUILD_TAGS)" -v -coverprofile=$(COVERAGE_DIR)/vtpm.out -covermode=atomic ./pkg/vtpm/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/vtpm.out -o $(COVERAGE_DIR)/vtpm.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/vtpm.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/vtpm.html$(RESET)"

# Code coverage targets

# Packages excluded from unit tests and coverage; their own tests run in no CI stage.
TEST_EXCLUDE := test/integration|sdk/go/gen|pkg/api/grpc/proto|pkg/api/grpc$$|cmd/platformctl$$|cmd/platformd$$|cmd/gatewayd$$|cmd/platform-initrd$$|examples/|pkg/webservice/v1/test$$|pkg/device/dao$$|pkg/dns/dao$$|pkg/platform$$|pkg/compute$$|pkg/qemu$$|pkg/swtpm$$|pkg/vtpm$$|pkg/sdn/netlink$$|pkg/ipxe$$|pkg/testenv$$|pkg/initrd$$|pkg/installer$$|pkg/installer/alpine$$|pkg/firstboot$$|pkg/uefi/firmware$$|pkg/uki$$|pkg/store/datastore$$|pkg/cli/commands$$|pkg/boot/commands$$|pkg/daemon/commands$$|pkg/sdn/gateway/commands$$|pkg/iso$$|pkg/storage/luks$$|pkg/compute/podman$$|pkg/cli$$|pkg/app$$|pkg/webservice$$|pkg/dns$$|pkg/webservice/v1$$|pkg/webservice/v1/webauthn$$|pkg/webservice/v1/rest/platform$$|pkg/platform/system$$

# TEST_UNIT_PKGS: excluded packages whose tests are self-contained, named explicitly so they stay in the suite.
TEST_UNIT_PKGS := ./pkg/app/ ./pkg/daemon/commands/ ./pkg/cli/commands/bootstrap/ ./pkg/webservice/v1/ ./pkg/dns/ ./pkg/cli/commands/admin/ ./pkg/platform/ ./pkg/swtpm/ ./pkg/vtpm/ ./pkg/firstboot/ ./test/integration/helpers/surface/ ./test/integration/helpers/ ./test/integration/bmc/vbmc/ ./test/integration/bmc/rmcpsim/ ./test/integration/iso/ ./test/integration/tenant/ ./scripts/depscheck/ ./scripts/foreignfailures/ ./internal/quicbaas/

# RACE_EXCLUDE: packages with known, tracked data races; ^$$ keeps the filter a no-op.
RACE_EXCLUDE := ^$$

.PHONY: test-race
## test-race: Run unit tests under the race detector; an empty package list is an error
RACE_PKGS_DISCOVER = \
	pkgs=$$(go list -tags "$(BUILD_TAGS)" ./pkg/... ./cmd/...); \
	pkgs=$$(printf '%s\n' "$$pkgs" | grep -v -E "$(TEST_EXCLUDE)" | grep -v -E "$(RACE_EXCLUDE)"); \
	[ -n "$$pkgs" ] || { echo "$@: package discovery produced no packages" >&2; exit 1; }; \
	pkgs=$$(printf '%s\n' $$pkgs $(TEST_UNIT_PKGS) | $(SHARD_PICK)); \
	[ -n "$$pkgs" ] || { echo "$@: shard $(SHARD) of $(SHARDS) has no packages" >&2; exit 1; }

test-race:
	@echo "Running unit tests under the race detector..."
	@set -e; \
	$(RACE_PKGS_DISCOVER); \
	go test -race -tags "$(BUILD_TAGS)" -skip "$(TEST_SKIP)" -timeout 20m $$pkgs

## print-race-pkgs: Print test-race's package set on one line
.PHONY: print-race-pkgs
print-race-pkgs:
	@set -e; \
	$(RACE_PKGS_DISCOVER); \
	echo $$pkgs

## print-test-skip: Print the TEST_SKIP pattern the unit suites pass to -skip
.PHONY: print-test-skip
print-test-skip:
	@echo '$(TEST_SKIP)'

.PHONY: coverage
## coverage: Run unit tests with coverage analysis
coverage:
	@echo "$(CYAN)$(BOLD)→ Running tests with coverage...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@{ $(GOTEST) -p 4 -tags "$(BUILD_TAGS) pkcs11 objstore" -coverprofile=$(COVERAGE_FILE) -covermode=atomic \
		$$(go list ./pkg/... ./cmd/... | grep -v -E "$(TEST_EXCLUDE)"); \
		echo $$? > $(COVERAGE_DIR)/test.status; } 2>&1 | tee $(COVERAGE_DIR)/test.log
	@TEST_EXIT=$$(cat $(COVERAGE_DIR)/test.status); rm -f $(COVERAGE_DIR)/test.status; \
	if [ -f $(COVERAGE_FILE) ]; then \
		echo ""; \
		echo "$(CYAN)$(BOLD)Coverage Summary$(RESET)"; \
		echo "$(CYAN)────────────────────────────────────────$(RESET)"; \
		awk -F'[: ,]' 'NR>1 {stmts+=$$(NF-1); if($$NF>0) covered+=$$(NF-1)} END{printf "  Total: %.1f%%\n", covered*100/stmts}' $(COVERAGE_FILE); \
		echo "$(CYAN)────────────────────────────────────────$(RESET)"; \
		echo "$(GREEN)✓ Coverage report: $(COVERAGE_FILE)$(RESET)"; \
	fi; \
	exit $$TEST_EXIT

.PHONY: coverage-report
## coverage-report: Generate HTML coverage report
coverage-report: coverage
	@echo "$(CYAN)→ Generating HTML coverage report...$(RESET)"
	@$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@COVERAGE=$$($(GO) tool cover -func=$(COVERAGE_FILE) | grep total | awk '{print $$3}'); \
	echo "$(GREEN)✓ Coverage report: $(COVERAGE_HTML)$(RESET)"; \
	echo "$(BOLD)$(BLUE)Coverage: $$COVERAGE$(RESET)"; \
	COVERAGE_NUM=$$(echo $$COVERAGE | sed 's/%//' | awk '{printf "%d", $$1}'); \
	if [ -z "$$COVERAGE_NUM" ]; then \
		echo "$(RED)✗ Coverage could not be determined$(RESET)"; \
		exit 1; \
	fi; \
	if [ $$COVERAGE_NUM -lt $(COVERAGE_THRESHOLD) ]; then \
		echo "$(RED)✗ Coverage $$COVERAGE is below the $(COVERAGE_THRESHOLD)% hard gate$(RESET)"; \
		exit 1; \
	fi; \
	echo "$(GREEN)✓ Coverage $$COVERAGE meets the $(COVERAGE_THRESHOLD)% threshold$(RESET)"

.PHONY: coverage-full
## coverage-full: Generate comprehensive coverage report (unit + quicbaas tests)
coverage-full:
	@echo "$(CYAN)$(BOLD)→ Running comprehensive coverage tests...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
# Both steps continue on failure; the merge needs both profiles.
	@echo "$(CYAN)→ Step 1: Running unit tests with coverage...$(RESET)"
	@{ $(GOTEST) -tags "$(BUILD_TAGS) pkcs11 objstore integration" -coverprofile=$(COVERAGE_DIR)/unit.out -covermode=atomic \
		$$(go list ./pkg/... ./cmd/... | grep -v -E "$(TEST_EXCLUDE)"); \
		echo $$? > $(COVERAGE_DIR)/unit.status; } 2>&1 | tee $(COVERAGE_DIR)/unit.log
	@echo "$(CYAN)→ Step 2: Running QuicBaaS tests with coverage...$(RESET)"
	@{ $(GOTEST) -tags "$(BUILD_TAGS)" -count=1 -parallel 1 -timeout 10m -coverprofile=$(COVERAGE_DIR)/quicbaas.out -covermode=atomic \
		./pkg/storage/quicbaas/...; \
		echo $$? > $(COVERAGE_DIR)/quicbaas.status; } 2>&1 | tee $(COVERAGE_DIR)/quicbaas.log
	@echo "$(CYAN)→ Merging coverage profiles...$(RESET)"
	@if command -v gocovmerge >/dev/null 2>&1; then \
		gocovmerge $(COVERAGE_DIR)/unit.out $(COVERAGE_DIR)/quicbaas.out > $(COVERAGE_FILE); \
	else \
		cp $(COVERAGE_DIR)/unit.out $(COVERAGE_FILE); \
		echo "$(YELLOW)⚠ gocovmerge not found - using unit coverage only$(RESET)"; \
		echo "$(YELLOW)  Install with: go install github.com/wadey/gocovmerge@latest$(RESET)"; \
	fi
	@$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@$(GO) tool cover -func=$(COVERAGE_FILE) | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_HTML)$(RESET)"
	@unit=$$(cat $(COVERAGE_DIR)/unit.status 2>/dev/null || echo 0); \
	qb=$$(cat $(COVERAGE_DIR)/quicbaas.status 2>/dev/null || echo 0); \
	rm -f $(COVERAGE_DIR)/unit.status $(COVERAGE_DIR)/quicbaas.status; \
	if [ "$$unit" -ne 0 ] || [ "$$qb" -ne 0 ]; then \
		echo "$(RED)✗ Coverage was measured over a FAILING run (unit=$$unit quicbaas=$$qb)$(RESET)"; \
		echo "$(RED)  The percentage above describes the tests that passed, not the suite.$(RESET)"; \
		exit 1; \
	fi

# Package-specific coverage targets
.PHONY: coverage-crypto
## coverage-crypto: Generate crypto package coverage report
coverage-crypto:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating crypto coverage report...$(RESET)"
	@$(GOTEST) -tags "$(BUILD_TAGS)" -v -coverprofile=$(COVERAGE_DIR)/crypto.out -covermode=atomic ./pkg/crypto/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/crypto.out -o $(COVERAGE_DIR)/crypto.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/crypto.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/crypto.html$(RESET)"

.PHONY: coverage-webservice
## coverage-webservice: Generate webservice package coverage report
coverage-webservice:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating webservice coverage report...$(RESET)"
	@$(GOTEST) -tags "$(BUILD_TAGS) pkcs11 objstore" -v -coverprofile=$(COVERAGE_DIR)/webservice.out -covermode=atomic ./pkg/webservice/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/webservice.out -o $(COVERAGE_DIR)/webservice.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/webservice.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/webservice.html$(RESET)"

.PHONY: coverage-platform
## coverage-platform: Generate platform package coverage report
coverage-platform:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating platform coverage report...$(RESET)"
	@$(GOTEST) -tags "$(BUILD_TAGS) pkcs11 objstore integration" -v -coverprofile=$(COVERAGE_DIR)/platform.out -covermode=atomic ./pkg/platform/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/platform.out -o $(COVERAGE_DIR)/platform.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/platform.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/platform.html$(RESET)"

## test-netplan: Unit tests for the network plan and the zone model
.PHONY: test-netplan
test-netplan:
	# tag-independent
	go test -count=1 -timeout 120s ./pkg/sdn/netplan/... ./pkg/sdn/zone/...

## coverage-netplan: Coverage report for the network plan and the zone model
.PHONY: coverage-netplan
coverage-netplan:
	@mkdir -p $(COVERAGE_DIR)
	# tag-independent
	go test -count=1 -timeout 120s -coverprofile=$(COVERAGE_DIR)/netplan.out -covermode=atomic \
		./pkg/sdn/netplan/... ./pkg/sdn/zone/...
	go tool cover -func=$(COVERAGE_DIR)/netplan.out | tail -1
	@go tool cover -html=$(COVERAGE_DIR)/netplan.out -o $(COVERAGE_DIR)/netplan.html

## bench-netplan: Benchmarks for plan derivation and lookups
.PHONY: bench-netplan
bench-netplan:
	# tag-independent
	go test -bench=. -benchmem -run=^$$ ./pkg/sdn/netplan/...

.PHONY: coverage-sdn
## coverage-sdn: Generate SDN package coverage report
coverage-sdn:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating SDN coverage report...$(RESET)"
	@$(GOTEST) -tags "$(BUILD_TAGS)" -v -coverprofile=$(COVERAGE_DIR)/sdn.out -covermode=atomic ./pkg/sdn/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/sdn.out -o $(COVERAGE_DIR)/sdn.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/sdn.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/sdn.html$(RESET)"

.PHONY: coverage-datastore
## coverage-datastore: Generate datastore package coverage report
coverage-datastore:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating datastore coverage report...$(RESET)"
	@$(GOTEST) -tags "$(BUILD_TAGS)" -v -coverprofile=$(COVERAGE_DIR)/datastore.out -covermode=atomic ./pkg/store/datastore/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/datastore.out -o $(COVERAGE_DIR)/datastore.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/datastore.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/datastore.html$(RESET)"

.PHONY: coverage-kms-rest
## coverage-kms-rest: Generate KMS REST API handlers coverage report
coverage-kms-rest:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating KMS REST handlers coverage report...$(RESET)"
	@$(GOTEST) -tags "$(BUILD_TAGS)" -v -coverprofile=$(COVERAGE_DIR)/kms-rest.out -covermode=atomic ./pkg/webservice/v1/rest/kms/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/kms-rest.out -o $(COVERAGE_DIR)/kms-rest.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/kms-rest.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/kms-rest.html$(RESET)"

.PHONY: coverage-kms-cli
## coverage-kms-cli: Generate KMS CLI commands coverage report
coverage-kms-cli:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating KMS CLI commands coverage report...$(RESET)"
	@$(GOTEST) -tags "$(BUILD_TAGS)" -v -coverprofile=$(COVERAGE_DIR)/kms-cli.out -covermode=atomic ./pkg/cli/commands/kms/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/kms-cli.out -o $(COVERAGE_DIR)/kms-cli.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/kms-cli.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/kms-cli.html$(RESET)"

.PHONY: test-tenant
## test-tenant: Run tenant package tests
test-tenant:
	@echo "$(CYAN)→ Running tenant package tests...$(RESET)"
	@$(GOTEST) -tags "$(BUILD_TAGS)" -v ./pkg/tenant/...
	@echo "$(GREEN)✓ Tenant tests complete$(RESET)"

.PHONY: coverage-tenant
## coverage-tenant: Generate tenant package coverage report
coverage-tenant:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating tenant package coverage report...$(RESET)"
	@$(GOTEST) -tags "$(BUILD_TAGS)" -v -coverprofile=$(COVERAGE_DIR)/tenant.out -covermode=atomic ./pkg/tenant/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/tenant.out -o $(COVERAGE_DIR)/tenant.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/tenant.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/tenant.html$(RESET)"

.PHONY: coverage-tenant-cli
## coverage-tenant-cli: Generate tenant CLI commands coverage report
coverage-tenant-cli:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating tenant CLI commands coverage report...$(RESET)"
	@$(GOTEST) -tags "$(BUILD_TAGS)" -v -coverprofile=$(COVERAGE_DIR)/tenant-cli.out -covermode=atomic ./pkg/cli/commands/tenant/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/tenant-cli.out -o $(COVERAGE_DIR)/tenant-cli.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/tenant-cli.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/tenant-cli.html$(RESET)"

.PHONY: integration-test-tenant
## integration-test-tenant: Run tenant multi-protocol integration tests in devcontainer
integration-test-tenant: build-devcontainer
	$(call run-integration-suite,tenant)

# Code quality targets

.PHONY: fmt
## fmt: Format all Go source files
fmt:
	@echo "$(CYAN)$(BOLD)→ Formatting Go source files...$(RESET)"
	@$(GOFMT) -s -w .
	@echo "$(GREEN)✓ Formatting complete$(RESET)"

.PHONY: fmt-check
## fmt-check: Check if Go source files are formatted
fmt-check:
	@echo "$(CYAN)$(BOLD)→ Checking Go source formatting...$(RESET)"
	@if [ -n "$$($(GOFMT) -l .)" ]; then \
		echo "$(RED)$(BOLD)✗ The following files need formatting:$(RESET)"; \
		$(GOFMT) -l .; \
		exit 1; \
	fi
	@echo "$(GREEN)✓ All files are properly formatted$(RESET)"

.PHONY: check-go-build-tags
## check-go-build-tags: Fail if a target CI calls drops GO_BUILD_TAGS
GO_BUILD_TAGS_PROBE     := probe_tag_960
GO_BUILD_TAGS_TARGETS   := lint build coverage security integration-test test
check-go-build-tags:
ifndef GO_BUILD_TAGS_PROBING
	@echo "$(CYAN)$(BOLD)→ Checking GO_BUILD_TAGS reaches $(GO_BUILD_TAGS_TARGETS)...$(RESET)"
	@for target in $(GO_BUILD_TAGS_TARGETS); do \
		$(MAKE) -n --no-print-directory $$target GO_BUILD_TAGS=$(GO_BUILD_TAGS_PROBE) GO_BUILD_TAGS_PROBING=1 2>&1 \
			| grep -v '^echo ' | grep -q -- '$(GO_BUILD_TAGS_PROBE)' || { \
			echo "$(RED)$(BOLD)✗ make $$target GO_BUILD_TAGS=$(GO_BUILD_TAGS_PROBE) never passes the tag to a command$(RESET)"; \
			exit 1; \
		}; \
	done
	@echo "$(GREEN)✓ GO_BUILD_TAGS reaches every ci-template target$(RESET)"
endif

.PHONY: lint-gates
## lint-gates: The repo's grep gates; CI runs them in the Lint Gates job beside Lint (ci-template v1.27)
lint-gates: check-insecure-tls

.PHONY: check-insecure-tls
## check-insecure-tls: Enforce InsecureSkipVerify allowlist (fails on unapproved use)
check-insecure-tls:
	@# Every allowlisted file below is a CAPTURE-ONLY dial: it exchanges no
	@# application data, and a real trust decision is made afterwards from
	@# the captured certificate. pkg/app/nts_provision.go is the NTS-KE
	@# inspection dial to 127.0.0.1 — the renewal sweep must read the
	@# certificate chronyd actually serves even while it is still the
	@# self-signed bootstrap one, then verifies it against the platform CA
	@# roots in ntsServedCertInvalid. See docs/ntp/architecture.md §3.
	@echo "$(CYAN)$(BOLD)→ Checking InsecureSkipVerify allowlist...$(RESET)"
	@violations=$$(grep -rPn 'InsecureSkipVerify[[:space:]]*:[[:space:]]*true' --include="*.go" . \
		| grep -Pv '^[^:]+:[0-9]+:[[:space:]]*//' \
		| grep -v 'pkg/bootstrap/virtual_media.go' \
		| grep -v 'pkg/bmc/discovery.go' \
		| grep -v 'pkg/cli/commands/bmc/standalone.go' \
		| grep -v 'test/integration/bmc/harness.go' \
		| grep -v 'pkg/app/nts_provision.go' \
		|| true); \
	if [ -n "$$violations" ]; then \
		echo "$(RED)$(BOLD)✗ FORBIDDEN InsecureSkipVerify outside allowlist:$(RESET)"; \
		printf '%s\n' "$$violations"; \
		exit 1; \
	fi
	@echo "$(GREEN)✓ InsecureSkipVerify allowlist check passed$(RESET)"
	@echo "$(CYAN)$(BOLD)→ Checking insecure.NewCredentials allowlist...$(RESET)"
	@# Fail-closed transports (#32): plaintext gRPC credentials are allowed
	@# ONLY for the Unix-domain-socket client transport — filesystem-
	@# permission-scoped, not network-exposed. Every other use is a
	@# plaintext network dial and a fail-open regression.
	@# Allowlist: sdk/go/transport/unix/adapter.go (UDS SDK client). The
	@# integration UDS dial (test/integration/helpers/mtls.go
	@# GRPCUnixCredentials) uses credentials/local, which refuses a non-local
	@# dial, and needs no entry.
	@violations=$$(grep -rn 'insecure\.NewCredentials' --include="*.go" . \
		| grep -Pv '^[^:]+:[0-9]+:[[:space:]]*//' \
		| grep -v 'sdk/go/transport/unix/adapter.go' \
		|| true); \
	if [ -n "$$violations" ]; then \
		echo "$(RED)$(BOLD)✗ FORBIDDEN insecure.NewCredentials outside the UDS allowlist:$(RESET)"; \
		printf '%s\n' "$$violations"; \
		exit 1; \
	fi
	@echo "$(GREEN)✓ insecure.NewCredentials allowlist check passed$(RESET)"


.PHONY: vet
## vet: Run go vet on all packages
vet:
	@echo "$(CYAN)$(BOLD)→ Running go vet...$(RESET)"
	@$(GOVET) -tags "$(BUILD_TAGS) pkcs11 objstore integration" ./...
	@echo "$(GREEN)✓ go vet complete$(RESET)"

.PHONY: lint-cli
## lint-cli: Verify CLI commands use SDK only — no direct protocol imports
lint-cli:
	@echo "Checking CLI commands for direct protocol imports..."
	@VIOLATIONS=$$(grep -rn 'pkg/api/rest\|pkg/api/quic\|pkg/api/mcp' pkg/cli/commands/ 2>/dev/null | grep -v '_test.go' || true); \
	if [ -n "$$VIOLATIONS" ]; then \
		echo "ERROR: CLI commands must not import protocol packages directly."; \
		echo "Use sdk/go transport abstractions instead."; \
		echo ""; \
		echo "$$VIOLATIONS"; \
		exit 1; \
	fi
	@echo "CLI lint passed — no direct protocol imports found."

.PHONY: lint
## lint: Run golangci-lint on all packages (GOLANGCI_LINT_TIMEOUT bounds the run; see its comment)
lint: $(GOLANGCI_LINT) $(ACTIONLINT)
	@echo "$(CYAN)$(BOLD)→ Running actionlint ($(ACTIONLINT_VERSION))...$(RESET)"
	@$(ACTIONLINT) || { echo "$(RED)$(BOLD)✗ actionlint failed$(RESET)"; exit 1; }
	@echo "$(CYAN)$(BOLD)→ Running linters ($(GOLANGCI_LINT_VERSION))...$(RESET)"
	@mkdir -p $(GOLANGCI_LINT_CACHE)
	@if $(GOLANGCI_LINT) run --allow-serial-runners --timeout=$(GOLANGCI_LINT_TIMEOUT) $(if $(GO_BUILD_TAGS_CSV),--build-tags=$(GO_BUILD_TAGS_CSV)) ./...; then \
		echo "$(GREEN)✓ Linting complete$(RESET)"; \
	else \
		echo "$(RED)$(BOLD)✗ Linting failed with errors$(RESET)"; \
		exit 1; \
	fi

# Security scanning targets

.PHONY: gosec
## gosec: Run security analysis with gosec
gosec: $(GOSEC)
	@echo "$(CYAN)$(BOLD)→ Running security analysis with gosec $(GOSEC_VERSION)...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	@rc=0; \
	$(GOSEC) -concurrency $(GOSEC_CONCURRENCY) -exclude=$(GOSEC_EXCLUDE) -severity medium -confidence medium \
		$(if $(GO_BUILD_TAGS_CSV),-tags=$(GO_BUILD_TAGS_CSV)) \
		-exclude-dir=test -exclude-dir=testdata -exclude-dir=vendor \
		-exclude-generated \
		-fmt=text -out=$(BUILD_DIR)/gosec-report.txt ./... 2>$(BUILD_DIR)/gosec-stderr.txt || rc=$$?; \
	if [ $$rc -eq 0 ]; then \
		echo "$(GREEN)✓ Security scan complete - no issues found$(RESET)"; \
		echo "$(CYAN)Report saved to: $(BUILD_DIR)/gosec-report.txt$(RESET)"; \
	elif grep -qE 'type errors|Golang errors in' $(BUILD_DIR)/gosec-report.txt $(BUILD_DIR)/gosec-stderr.txt; then \
		echo "$(RED)$(BOLD)✗ gosec could not analyze the module (packages failed to type-check; not a findings failure). First errors:$(RESET)"; \
		grep -hE 'Golang errors in|^  > |type errors' $(BUILD_DIR)/gosec-report.txt $(BUILD_DIR)/gosec-stderr.txt | head -n 5; \
		echo "$(YELLOW)  Full report: $(BUILD_DIR)/gosec-report.txt$(RESET)"; \
		exit $$rc; \
	else \
		echo "$(RED)$(BOLD)✗ Security issues found (gosec exit $$rc):$(RESET)"; \
		cat $(BUILD_DIR)/gosec-stderr.txt $(BUILD_DIR)/gosec-report.txt; \
		exit $$rc; \
	fi

.PHONY: gosec-sarif
## gosec-sarif: Run gosec and output SARIF format for GitHub Security tab
gosec-sarif: $(GOSEC)
	@echo "$(CYAN)$(BOLD)→ Running gosec $(GOSEC_VERSION) with SARIF output...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	@# Findings do not fail this target (the SARIF file carries them); only a
	@# run that produced no report at all (type errors, crash) does.
	@rm -f $(BUILD_DIR)/gosec-results.sarif
	@$(GOSEC) -concurrency $(GOSEC_CONCURRENCY) -exclude=$(GOSEC_EXCLUDE) -severity medium -confidence medium \
		-exclude-dir=test -exclude-dir=testdata -exclude-dir=vendor \
		-exclude-generated \
		-fmt=sarif -out=$(BUILD_DIR)/gosec-results.sarif ./... || true
	@if [ ! -s $(BUILD_DIR)/gosec-results.sarif ]; then \
		echo "$(RED)$(BOLD)✗ gosec produced no SARIF report$(RESET)"; \
		exit 1; \
	fi
	@echo "$(GREEN)✓ SARIF report: $(BUILD_DIR)/gosec-results.sarif$(RESET)"

# Modules `make vuln` scans: the root module and sdk/go.
GOVULN_MODULES := . sdk/go

# govulncheck allowlist, IDs with no fixed release (any other finding fails): GO-2026-4736 gobgp/v4 NEXT_HOP panic, speaker peers only with configured neighbours (#25); GO-2026-6911 mcp-go client transport, test-only use (#1422). Delete an ID when its fix ships.
GOVULN_ALLOW := GO-2026-4736 GO-2026-6911

# Each module is scanned for vulnerable imports first; the symbol scan runs only for an import outside the allowlist.
.PHONY: vuln
## vuln: Run vulnerability scan with govulncheck (allowlist: GOVULN_ALLOW)
vuln:
	@echo "$(CYAN)$(BOLD)→ Running vulnerability scan with govulncheck...$(RESET)"
	@GOVULNCHECK_BIN=$$(command -v govulncheck 2>/dev/null || echo "$$HOME/go/bin/govulncheck"); \
	if [ ! -x "$$GOVULNCHECK_BIN" ]; then \
		echo "$(YELLOW)⚠ govulncheck not found$(RESET)"; \
		echo "$(YELLOW)  Install with: make install-govulncheck$(RESET)"; \
		exit 1; \
	fi; \
	scan() { \
		OUT=$$(cd $$1 && $$GOVULNCHECK_BIN -scan $$2 $(if $(GO_BUILD_TAGS_CSV),-tags=$(GO_BUILD_TAGS_CSV)) ./... 2>&1); STATUS=$$?; \
		echo "$$OUT"; \
		if [ $$STATUS -ne 0 ] && [ $$STATUS -ne 3 ]; then \
			echo "$(RED)✗ govulncheck -scan $$2 could not complete in $$1 (exit $$STATUS)$(RESET)"; \
			echo "$(RED)  A scan that fails to run is not a pass — fix the error above.$(RESET)"; \
			exit 1; \
		fi; \
		FOUND=$$(echo "$$OUT" | sed -n 's/^Vulnerability #[0-9]*: \(GO-[0-9][0-9-]*\).*/\1/p' | sort -u); \
		for id in $(GOVULN_ALLOW); do FOUND=$$(echo "$$FOUND" | grep -vx "$$id" || true); done; \
		FOUND=$$(echo $$FOUND); \
	}; \
	FAILED=0; \
	for mod in $(GOVULN_MODULES); do \
		echo "$(CYAN)  scanning module $$mod (imported packages)$(RESET)"; \
		scan $$mod package; \
		if [ -n "$$FOUND" ]; then \
			echo "$(CYAN)  $$mod imports $$FOUND outside the allowlist; scanning module $$mod (called symbols)$(RESET)"; \
			scan $$mod symbol; \
		fi; \
		if [ -n "$$FOUND" ]; then \
			echo "$(RED)✗ $$mod: vulnerabilities outside the documented allowlist: $$FOUND$(RESET)"; \
			echo "$(RED)  Fix them or record an exception in GOVULN_ALLOW with a reason and a date.$(RESET)"; \
			FAILED=1; \
		fi; \
	done; \
	if [ $$FAILED -ne 0 ]; then exit 1; fi; \
	echo "$(GREEN)✓ Vulnerability scan complete (only allowlisted no-fix findings remain)$(RESET)"

# Directories excluded from the filesystem scan.
TRIVY_SKIP_DIRS := --skip-dirs test --skip-dirs examples --skip-dirs vbmc --skip-dirs web/node_modules

.PHONY: trivy
## trivy: Run Trivy vulnerability scan on filesystem
trivy:
	@echo "$(CYAN)$(BOLD)→ Running Trivy vulnerability scan...$(RESET)"
	@TRIVY_BIN=$$(command -v trivy 2>/dev/null); \
	if [ -n "$$TRIVY_BIN" ]; then \
		$$TRIVY_BIN fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 \
			$(TRIVY_SKIP_DIRS) . && \
		echo "$(GREEN)✓ Trivy scan complete - no critical/high vulnerabilities found$(RESET)"; \
	else \
		echo "$(RED)$(BOLD)✗ trivy not found on PATH - the security suite cannot pass without it$(RESET)"; \
		echo "$(YELLOW)  Install with: make install-trivy$(RESET)"; \
		exit 1; \
	fi

.PHONY: trivy-image
## trivy-image: Run Trivy vulnerability scan on Docker image
trivy-image:
	@echo "$(CYAN)$(BOLD)→ Running Trivy vulnerability scan on Docker image...$(RESET)"
	@TRIVY_BIN=$$(command -v trivy 2>/dev/null); \
	if [ -n "$$TRIVY_BIN" ]; then \
		$$TRIVY_BIN image --severity CRITICAL,HIGH $(APPNAME)-builder-$(DOCKER_BUILDER_BASE):amd64 && \
		echo "$(GREEN)✓ Trivy image scan complete$(RESET)"; \
	else \
		echo "$(YELLOW)⚠ trivy not found$(RESET)"; \
		echo "$(YELLOW)  Install with: make install-trivy$(RESET)"; \
		exit 1; \
	fi

.PHONY: grype
## grype: Run Grype vulnerability scan on Docker image
grype:
	@echo "$(CYAN)$(BOLD)→ Running Grype vulnerability scan...$(RESET)"
	@GRYPE_BIN=$$(command -v grype 2>/dev/null); \
	if [ -n "$$GRYPE_BIN" ]; then \
		$$GRYPE_BIN $(APPNAME)-builder-$(DOCKER_BUILDER_BASE):amd64 --fail-on high && \
		echo "$(GREEN)✓ Grype scan complete$(RESET)"; \
	else \
		echo "$(YELLOW)⚠ grype not found$(RESET)"; \
		echo "$(YELLOW)  Install with: make install-grype$(RESET)"; \
		exit 1; \
	fi

.PHONY: mod-verify
## mod-verify: Verify module integrity against go.sum (root and sdk/go)
mod-verify:
	@echo "$(CYAN)$(BOLD)→ Verifying module integrity...$(RESET)"
	@$(GO) mod verify
	@cd sdk/go && $(GO) mod verify
	@echo "$(GREEN)✓ Module integrity verified$(RESET)"

.PHONY: security
## security: Run gosec, govulncheck, go mod verify and trivy fs
security: gosec vuln mod-verify trivy
	@echo "$(GREEN)$(BOLD)✓ Security suite passed!$(RESET)"

.PHONY: security-novuln
## security-novuln: make security without govulncheck; CI runs vuln as its own job
security-novuln: gosec mod-verify trivy
	@echo "$(GREEN)$(BOLD)✓ Security suite (without govulncheck) passed!$(RESET)"

.PHONY: check
## check: Run all code quality and security checks
check: fmt-check vet lint gosec vuln
	@echo "$(GREEN)$(BOLD)✓ All quality checks passed!$(RESET)"

# Tool installation targets

.PHONY: install-tools
## install-tools: Install all development and security tools
install-tools: install-gosec install-govulncheck install-trivy install-grype install-golangci-lint install-gocovmerge
	@echo "$(GREEN)$(BOLD)✓ All development tools installed$(RESET)"

.PHONY: install-gosec
## install-gosec: Install gosec security scanner
install-gosec: $(GOSEC)
	@echo "$(GREEN)  ✓ gosec $(GOSEC_VERSION) at $(GOSEC)$(RESET)"

# Built from $(GOSEC_SRC) with this module's toolchain into a version-stamped directory.
$(GOSEC):
	@echo "$(CYAN)$(BOLD)→ Building gosec $(GOSEC_VERSION) from $(GOSEC_SRC) (module toolchain, x/tools v0.51.0)...$(RESET)"
	@mkdir -p $(GOSEC_DIR)
	@go build -C $(GOSEC_SRC) -o $(abspath $(GOSEC)) github.com/securego/gosec/v2/cmd/gosec

.PHONY: install-govulncheck
## install-govulncheck: Install govulncheck vulnerability scanner
install-govulncheck:
	@echo "$(CYAN)$(BOLD)→ Installing govulncheck...$(RESET)"
	@if ! command -v govulncheck >/dev/null 2>&1; then \
		echo "$(CYAN)  Installing govulncheck vulnerability scanner...$(RESET)"; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
		echo "$(GREEN)  ✓ govulncheck installed$(RESET)"; \
	else \
		echo "$(GREEN)  ✓ govulncheck already installed$(RESET)"; \
	fi

.PHONY: install-trivy
## install-trivy: Install Trivy vulnerability scanner
install-trivy:
	@echo "$(CYAN)$(BOLD)→ Installing trivy...$(RESET)"
	@if ! command -v trivy >/dev/null 2>&1; then \
		echo "$(CYAN)  Installing Trivy vulnerability scanner...$(RESET)"; \
		curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b $$(go env GOPATH)/bin; \
		echo "$(GREEN)  ✓ trivy installed$(RESET)"; \
	else \
		echo "$(GREEN)  ✓ trivy already installed$(RESET)"; \
	fi

.PHONY: install-grype
## install-grype: Install Grype vulnerability scanner
install-grype:
	@echo "$(CYAN)$(BOLD)→ Installing grype...$(RESET)"
	@if ! command -v grype >/dev/null 2>&1; then \
		echo "$(CYAN)  Installing Grype vulnerability scanner...$(RESET)"; \
		curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b $$(go env GOPATH)/bin; \
		echo "$(GREEN)  ✓ grype installed$(RESET)"; \
	else \
		echo "$(GREEN)  ✓ grype already installed$(RESET)"; \
	fi

.PHONY: install-golangci-lint
## install-golangci-lint: Install golangci-lint
install-golangci-lint: $(GOLANGCI_LINT)
	@echo "$(GREEN)  ✓ golangci-lint $(GOLANGCI_LINT_VERSION) at $(GOLANGCI_LINT)$(RESET)"

# Builds the pinned linter into a version-stamped directory under $(BUILD_DIR).
$(GOLANGCI_LINT):
	@echo "$(CYAN)$(BOLD)→ Installing golangci-lint $(GOLANGCI_LINT_VERSION) (built with this module's toolchain)...$(RESET)"
	@mkdir -p $(GOLANGCI_LINT_DIR)
	@go build -C $(GOLANGCI_LINT_SRC) -mod=readonly -o $(abspath $(GOLANGCI_LINT)) github.com/golangci/golangci-lint/v2/cmd/golangci-lint

$(ACTIONLINT):
	@echo "$(CYAN)$(BOLD)→ Installing actionlint $(ACTIONLINT_VERSION) (built with this module's toolchain)...$(RESET)"
	@mkdir -p $(ACTIONLINT_DIR)
	@go build -C $(ACTIONLINT_SRC) -mod=readonly -o $(abspath $(ACTIONLINT)) github.com/rhysd/actionlint/cmd/actionlint

.PHONY: install-gocovmerge
## install-gocovmerge: Install gocovmerge for merging coverage files
install-gocovmerge:
	@echo "$(CYAN)$(BOLD)→ Installing gocovmerge...$(RESET)"
	@if ! command -v gocovmerge >/dev/null 2>&1; then \
		echo "$(CYAN)  Installing gocovmerge...$(RESET)"; \
		go install github.com/wadey/gocovmerge@latest; \
		echo "$(GREEN)  ✓ gocovmerge installed$(RESET)"; \
	else \
		echo "$(GREEN)  ✓ gocovmerge already installed$(RESET)"; \
	fi

# CI pipeline targets

.PHONY: ci-local
## ci-local: Run the CI pipeline locally (requires all tools installed)
ci-local: fmt-check vet lint security build-no-web test
	@echo "$(GREEN)$(BOLD)✓ CI pipeline complete!$(RESET)"

.PHONY: ci
## ci: Run CI pipeline in Docker container
ci: docker-builder-load-ci
	@echo "$(CYAN)$(BOLD)→ Running CI pipeline in Docker container...$(RESET)"
	docker run --rm --privileged \
		-v $(PWD):/workspace \
		$(DOCKER_MODULE_MOUNTS) \
		-w /workspace \
		$(APPNAME)-builder-$(DOCKER_BUILDER_BASE):amd64 \
		/bin/sh -c "make install-tools ci-local 2>&1"
	@echo "$(GREEN)$(BOLD)✓ CI pipeline complete!$(RESET)"

.PHONY: race
## race: Run tests with the race detector
race:
	@echo "$(CYAN)$(BOLD)→ Running tests with race detector...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	@{ $(GOTEST) -tags "pkcs11 objstore integration" -race -timeout 10m \
		$$(go list ./pkg/... | grep -v -E "(test/integration|storage/quicbaas)"); \
		echo $$? > $(BUILD_DIR)/race.status; } 2>&1 | tee $(BUILD_DIR)/race.log
	@status=$$(cat $(BUILD_DIR)/race.status); rm -f $(BUILD_DIR)/race.status; \
	if [ "$$status" -ne 0 ]; then \
		echo "$(RED)✗ Race detector run FAILED (exit $$status) — see $(BUILD_DIR)/race.log$(RESET)"; \
		exit "$$status"; \
	fi; \
	echo "$(GREEN)✓ Race detection complete — no races detected$(RESET)"

# Releases

.PHONY: release
release: clean \
	release-version-bump \
	release-commit \
	docker-builder-push \
	docker-platform-push \
	docker-pxe-server-push \
	docker-nfs-server-push \
	release-public-html \
	release-binaries \
	isos \
	release-github

.PHONY: release-local
release-local: clean \
	docker-builder-load \
	docker-platform-load \
	docker-pxe-server-load \
	docker-nfs-server-load \
	release-public-html \
	release-binaries \
	isos

.PHONY: release-commit
release-commit:
	git add -A
	git commit -F CHANGELOG
	git push origin $(GIT_BRANCH)

.PHONY: release-binaries
release-binaries:
	# glibc
	CONTAINER=$$(docker create $(APPNAME)-builder-debian:amd64); \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD) $(PLATFORMD)-glibc-x86_64; \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD) $(PLATFORMD)-debug-glibc-x86_64
	CONTAINER=$$(docker create $(APPNAME)-builder-debian:arm64); \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD) $(PLATFORMD)-glibc-aarch64; \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD) $(PLATFORMD)-debug-glibc-aarch64
	# musl (now static by default)
	CONTAINER=$$(docker create $(APPNAME)-builder-alpine:amd64); \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD) $(PLATFORMD)-musl-x86_64; \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD) $(PLATFORMD)-static-musl-x86_64; \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD) $(PLATFORMD)-debug-static-musl-x86_64
	CONTAINER=$$(docker create $(APPNAME)-builder-alpine:arm64); \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD) $(PLATFORMD)-musl-aarch64; \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD) $(PLATFORMD)-static-musl-aarch64; \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD) $(PLATFORMD)-debug-static-musl-aarch64

.PHONY:
release-public-html:
	CONTAINER=$$(docker create $(APPNAME)-builder-debian:amd64); \
		docker cp $$CONTAINER:/builder/go-trusted-platform/public_html/ .; \
		tar czf public_html.tar.gz public_html

.PHONY: release-version-bump
release-version-bump:
	@if [ -z "$(RELEASE_TYPE)" ]; then \
		echo "Error: RELEASE_TYPE must be specified (e.g., make increment_version RELEASE_TYPE=major)"; \
		exit 1; \
	fi
	@if [ ! -f $(VERSION_FILE) ]; then \
		echo "Error: VERSION file not found"; \
		exit 1; \
	fi
	@OLD_VERSION=$$(cat $(VERSION_FILE)); \
	MAJOR=$$(echo $$OLD_VERSION | cut -d. -f1); \
	MINOR=$$(echo $$OLD_VERSION | cut -d. -f2); \
	BUGFIX=$$(echo $$OLD_VERSION | cut -d. -f3 | cut -d- -f1); \
	PRERELEASE=$$(echo $$OLD_VERSION | grep -o -E '(-.*|$$)'); \
	if [ "$(RELEASE_TYPE)" = "major" ]; then \
		NEW_MAJOR=$$((MAJOR + 1)); \
		NEW_VERSION="$$NEW_MAJOR.0.0"; \
	elif [ "$(RELEASE_TYPE)" = "minor" ]; then \
		NEW_MINOR=$$((MINOR + 1)); \
		NEW_VERSION="$$MAJOR.$$NEW_MINOR.0"; \
	elif [ "$(RELEASE_TYPE)" = "bugfix" ]; then \
		NEW_BUGFIX=$$((BUGFIX + 1)); \
		NEW_VERSION="$$MAJOR.$$MINOR.$$NEW_BUGFIX"; \
	else \
		echo "Error: Invalid RELEASE_TYPE. Use 'major', 'minor', or 'bugfix'."; \
		exit 1; \
	fi; \
	if [ -n "$$PRERELEASE" ]; then \
		NEW_VERSION="$$NEW_VERSION$$PRERELEASE"; \
	fi; \
	echo $$NEW_VERSION > $(VERSION_FILE); \
	echo "Version updated: $$OLD_VERSION -> $$NEW_VERSION"

.PHONY: release-github
release-github:
	@VERSION=$$(cat $(VERSION_FILE)); \
	echo "Creating GitHub release v$$VERSION..."; \
	gh release create v$$VERSION \
		-t "v$$VERSION" \
		-F CHANGELOG \
		$(PLATFORMD)-debug-glibc-aarch64 \
		$(PLATFORMD)-debug-glibc-x86_64 \
		$(PLATFORMD)-debug-musl-aarch64 \
		$(PLATFORMD)-debug-musl-x86_64 \
		$(PLATFORMD)-debug-static-musl-aarch64 \
		$(PLATFORMD)-debug-static-musl-x86_64 \
		$(PLATFORMD)-glibc-aarch64 \
		$(PLATFORMD)-glibc-x86_64 \
		$(PLATFORMD)-musl-aarch64 \
		$(PLATFORMD)-musl-x86_64 \
		$(PLATFORMD)-static-musl-aarch64 \
		$(PLATFORMD)-static-musl-x86_64 \
		trusted-platform.iso \
		$(WEB_PUBLIC_HTML).tar.gz

.PHONY: release-github-delete
release-github-delete:
	@VERSION=$$(cat $(VERSION_FILE)); \
	echo "Deleting GitHub release v$$VERSION..."; \
	gh release delete v$$VERSION --yes; \
	git push origin --delete v$$VERSION


# Docker; both bake groups run on the default buildx builder, arm64 through binfmt.
.PHONY: docker-bake-load
docker-bake-load:
	docker buildx bake amd64 arm64 --load

.PHONY: docker-bake-push
docker-bake-push:
	docker buildx bake amd64 arm64 --push

# Docker :: PXE server
.PHONY: docker-pxe-server-load
docker-pxe-server-load:
	cd build/docker/pxe-server && make -j$(shell nproc) build

.PHONY: docker-pxe-server-push
docker-pxe-server-push:
	cd build/docker/pxe-server && make -j$(shell nproc) push

# PXE boot container: the static pxeboot binary, Samba and supervisord.
PXEBOOT_IMAGE               ?= platform-pxeboot
PXEBOOT_CONTEXT             := build/docker/bootstrap
PXEBOOT_BINARY              := $(PXEBOOT_CONTEXT)/pxeboot

.PHONY: pxeboot-container
pxeboot-container: pxeboot-binary
	@echo "$(CYAN)→ Building PXE boot container...$(RESET)"
	docker build \
		-t $(PXEBOOT_IMAGE):latest \
		-t $(PXEBOOT_IMAGE):$(APP_VERSION) \
		$(PXEBOOT_CONTEXT)
	@echo "$(GREEN)✓ PXE boot container built: $(PXEBOOT_IMAGE):$(APP_VERSION)$(RESET)"

.PHONY: pxeboot-binary
pxeboot-binary:
	@echo "$(CYAN)→ Building pxeboot binary (static)...$(RESET)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBIN)/go build \
		-tags "$(BUILD_TAGS)" \
		-o $(PXEBOOT_BINARY) \
		-ldflags="-w -s ${LDFLAGS}" \
		./cmd/pxeboot
	@echo "Binary size: $$(du -h $(PXEBOOT_BINARY) | cut -f1)"

.PHONY: pxeboot-container-save
pxeboot-container-save:
	@echo "$(CYAN)→ Saving PXE boot container as tar...$(RESET)"
	docker save $(PXEBOOT_IMAGE):latest > $(PXEBOOT_IMAGE).tar
	@echo "$(GREEN)✓ Saved: $(PXEBOOT_IMAGE).tar ($$(du -h $(PXEBOOT_IMAGE).tar | cut -f1))$(RESET)"

.PHONY: pxeboot-container-clean
pxeboot-container-clean:
	@rm -f $(PXEBOOT_BINARY)
	@docker rmi $(PXEBOOT_IMAGE):latest $(PXEBOOT_IMAGE):$(APP_VERSION) 2>/dev/null || true

# Docker :: NFS server
.PHONY: docker-nfs-server-load
docker-nfs-server-load:
	cd build/docker/nfs-server && make -j$(shell nproc) build

.PHONY: docker-nfs-server-push
docker-nfs-server-push:
	cd build/docker/nfs-server && make -j$(shell nproc) push

# Docker :: Trusted Platform Builder :: CI (amd64 only)
.PHONY: docker-builder-load-ci
docker-builder-load-ci:
	$(MAKE) docker-builder-load-amd64

# Docker :: Trusted Platform Builder :: Local
.PHONY: docker-builder-load
docker-builder-load:
	@start_time=$$(date +%s); \
		$(MAKE) \
			docker-builder-load-debian \
			docker-builder-load-alpine; \
	end_time=$$(date +%s); \
	elapsed_time=$$((end_time - start_time)); \
	hours=$$((elapsed_time/3600)); \
	minutes=$$(( (elapsed_time % 3600)/60 )); \
	seconds=$$((elapsed_time % 60)); \
	printf "${GREEN}Build execution time: %02d:%02d:%02d${NO_COLOR}\n" $$hours $$minutes $$seconds

docker-builder-load-alpine:
	@start_time=$$(date +%s); \
		$(MAKE) \
			docker-builder-load-amd64 \
			docker-builder-load-aarch64; \
	end_time=$$(date +%s); \
	elapsed_time=$$((end_time - start_time)); \
	hours=$$((elapsed_time/3600)); \
	minutes=$$(( (elapsed_time % 3600)/60 )); \
	seconds=$$((elapsed_time % 60)); \
	printf "${GREEN}Alpine build execution time: %02d:%02d:%02d${NO_COLOR}\n" $$hours $$minutes $$seconds

docker-builder-load-debian:
	@start_time=$$(date +%s); \
		DOCKER_BUILDER_BASE=debian $(MAKE) \
			docker-builder-load-amd64 \
			docker-builder-load-aarch64; \
	end_time=$$(date +%s); \
	elapsed_time=$$((end_time - start_time)); \
	hours=$$((elapsed_time/3600)); \
	minutes=$$(( (elapsed_time % 3600)/60 )); \
	seconds=$$((elapsed_time % 60)); \
	printf "${GREEN}Debian build execution time: %02d:%02d:%02d${NO_COLOR}\n" $$hours $$minutes $$seconds

.PHONY: docker-builder-load-amd64
docker-builder-load-amd64:
	BUILDKIT_DEBUG=1 docker buildx build --load \
		--pull \
		--progress=plain \
	 	--platform=linux/amd64 \
		-t $(APPNAME)-builder-$(DOCKER_BUILDER_BASE):amd64 \
		-f build/docker/$(APPNAME)-builder/$(DOCKER_BUILDER_DOCKERFILE) .

# U-Boot for the Raspberry Pi factory image, rpi_arm64 and qemu_arm64, with measured boot and Secure Boot keys from UBOOT_KEYS_DIR.
UBOOT_KEYS_DIR   ?= $(HOME)/.trusted-platform/secure-boot
UBOOT_OUTPUT_DIR ?= build/docker/uboot-builder/output

.PHONY: uboot-build
## uboot-build: Build the rpi_arm64 and qemu_arm64 U-Boot binaries with the Secure Boot keys from UBOOT_KEYS_DIR preseeded
uboot-build:
	$(MAKE) -C build/docker/uboot-builder build KEYS_DIR=$(abspath $(UBOOT_KEYS_DIR)) OUTPUT_DIR=$(abspath $(UBOOT_OUTPUT_DIR))

# iPXE: the arm64 EFI iPXE the PXE server hands to a Raspberry Pi or the QEMU virt stand-in.
IPXE_OUTPUT_DIR ?= build/docker/ipxe-builder/output
IPXE_ARM64_EFI  := $(IPXE_OUTPUT_DIR)/bin-arm64-efi/snponly.efi

.PHONY: ipxe-build
## ipxe-build: Build the arm64 EFI iPXE for network-booting AArch64 nodes (cached by its inputs' digests)
ipxe-build:
	$(MAKE) -C build/docker/ipxe-builder build OUTPUT_DIR=$(abspath $(IPXE_OUTPUT_DIR))

.PHONY: ipxe-verify
## ipxe-verify: Recompute the SHA256SUMS of the built iPXE
ipxe-verify:
	$(MAKE) -C build/docker/ipxe-builder verify OUTPUT_DIR=$(abspath $(IPXE_OUTPUT_DIR))

# The virt kernel for the QEMU virt stand-in, with the memory-mapped TIS TPM driver.
VIRT_KERNEL_OUTPUT_DIR ?= build/docker/virt-kernel-builder/output

.PHONY: virt-kernel-build
## virt-kernel-build: Cross-build the aarch64 virt kernel for the QEMU stand-in (cached by its inputs' digests)
virt-kernel-build:
	$(MAKE) -C build/docker/virt-kernel-builder build OUTPUT_DIR=$(abspath $(VIRT_KERNEL_OUTPUT_DIR))

.PHONY: virt-kernel-verify
## virt-kernel-verify: Recompute the SHA256SUMS of the built virt kernel
virt-kernel-verify:
	$(MAKE) -C build/docker/virt-kernel-builder verify OUTPUT_DIR=$(abspath $(VIRT_KERNEL_OUTPUT_DIR))

.PHONY: virt-kernel-clean
## virt-kernel-clean: Remove the built virt kernel
virt-kernel-clean:
	$(MAKE) -C build/docker/virt-kernel-builder clean OUTPUT_DIR=$(abspath $(VIRT_KERNEL_OUTPUT_DIR))

# The platform-required kernel options checked against the Alpine kernels the platform ships.
KERNEL_CONFIG_ALPINE_RELEASE ?= 3.22

.PHONY: kernel-config-check-alpine
## kernel-config-check-alpine: Check Alpine's linux-lts (x86_64, aarch64) and linux-rpi kernel configs against the platform-required options
kernel-config-check-alpine:
	@rc=0; \
	docker run --rm --platform linux/arm64 -v $(PWD)/build/docker/kernel-config:/kc:ro \
		alpine:$(KERNEL_CONFIG_ALPINE_RELEASE) /bin/sh /kc/check-alpine-kernels.sh linux-lts linux-rpi || rc=$$?; \
	docker run --rm --platform linux/amd64 -v $(PWD)/build/docker/kernel-config:/kc:ro \
		alpine:$(KERNEL_CONFIG_ALPINE_RELEASE) /bin/sh /kc/check-alpine-kernels.sh linux-lts || rc=$$?; \
	exit $$rc

.PHONY: uboot-verify
## uboot-verify: Recompute the SHA256SUMS of the built U-Boot artifacts
uboot-verify:
	$(MAKE) -C build/docker/uboot-builder verify OUTPUT_DIR=$(abspath $(UBOOT_OUTPUT_DIR))

.PHONY: uboot-clean
## uboot-clean: Remove the built U-Boot artifacts
uboot-clean:
	$(MAKE) -C build/docker/uboot-builder clean OUTPUT_DIR=$(abspath $(UBOOT_OUTPUT_DIR))

# strongSwan for the overlay's IPsec transport (build/docker/strongswan-builder), signature- and hash-checked, for amd64 and arm64.
STRONGSWAN_OUTPUT_DIR ?= build/docker/strongswan-builder/output
STRONGSWAN_ARCHES     ?= amd64 arm64

.PHONY: strongswan-build
## strongswan-build: Build the signed strongSwan and PKCS#11 module-host apks (amd64, arm64) from the signature-verified strongSwan release
strongswan-build: ipsec-module-host
	$(MAKE) -C build/docker/strongswan-builder build OUTPUT_DIR=$(abspath $(STRONGSWAN_OUTPUT_DIR)) ARCHES="$(STRONGSWAN_ARCHES)" \
		XKMS_VERSION=$(IPSEC_XKMS_VERSION) MODULE_HOST_DIR=$(abspath $(IPSEC_WORK_DIR))

.PHONY: strongswan-verify
## strongswan-verify: Re-verify the strongSwan and module-host apks: SHA256SUMS, apk and APKINDEX signatures, plugin set, source signature
strongswan-verify:
	$(MAKE) -C build/docker/strongswan-builder verify OUTPUT_DIR=$(abspath $(STRONGSWAN_OUTPUT_DIR)) ARCHES="$(STRONGSWAN_ARCHES)" XKMS_VERSION=$(IPSEC_XKMS_VERSION)

.PHONY: strongswan-clean
## strongswan-clean: Remove the built strongSwan apks (and a dev build's ephemeral signing key)
strongswan-clean:
	$(MAKE) -C build/docker/strongswan-builder clean OUTPUT_DIR=$(abspath $(STRONGSWAN_OUTPUT_DIR))

# The ipsec integration suite: two charon peers in network namespaces, IKEv2 through the go-xkms PKCS#11 module.
IPSEC_WORK_DIR     := work/ipsec
IPSEC_ARCHES       := amd64 arm64
IPSEC_PEER_IMAGE   := trusted-platform-ipsec-peer
IPSEC_HOST_IMAGE   := trusted-platform-ipsec-modulehost
IPSEC_XKMS_VERSION ?= v0.48.0-alpha
# --init: the peers' OpenRC services run supervise-daemon.
IPSEC_SUITE_ENV := --init \
	-e IPSEC_ROOTFS_AMD64=/workspace/$(IPSEC_WORK_DIR)/rootfs-amd64.tar \
	-e IPSEC_ROOTFS_ARM64=/workspace/$(IPSEC_WORK_DIR)/rootfs-arm64.tar \
	-e IPSEC_VM_KERNEL=/workspace/$(IPSEC_WORK_DIR)/vm/Image \
	-e IPSEC_VM_INITRD=/workspace/$(IPSEC_WORK_DIR)/vm/initrd.gz \
	-e IPSEC_TEST_ARM64=/workspace/$(IPSEC_WORK_DIR)/ipsec-arm64.test \
	-e IPSEC_WORK_DIR=/tmp/ipsec-integration

.PHONY: ipsec-peer-rootfs
## ipsec-peer-rootfs: Export the ipsec suite's Alpine peer root filesystems (amd64, arm64) with the strongSwan apks installed
ipsec-peer-rootfs:
	@mkdir -p $(IPSEC_WORK_DIR)
	@for a in $(IPSEC_ARCHES); do \
		docker build --platform linux/$$a --build-context apks=$(abspath $(STRONGSWAN_OUTPUT_DIR)) \
			-t $(IPSEC_PEER_IMAGE):$$a test/integration/ipsec/peer || exit 1; \
		cid=$$(docker create --platform linux/$$a $(IPSEC_PEER_IMAGE):$$a) || exit 1; \
		docker export -o $(IPSEC_WORK_DIR)/rootfs-$$a.tar $$cid; rc=$$?; \
		docker rm $$cid >/dev/null; \
		[ $$rc -eq 0 ] || exit $$rc; \
		echo "$(IPSEC_WORK_DIR)/rootfs-$$a.tar"; \
	done

.PHONY: ipsec-pkcs11-module
## ipsec-pkcs11-module: Build the go-xkms PKCS#11 module (IPSEC_XKMS_VERSION) c-shared against glibc, amd64 and arm64
ipsec-pkcs11-module:
	@mkdir -p $(IPSEC_WORK_DIR)/xkms-module
	@# A throwaway module that requires exactly the pinned go-xkms release (its
	@# sdk/go is a nested module, so the go-xkms tree itself cannot be built
	@# from the module cache). Resolving it here, on the host, fills the module
	@# cache through the host's credentials; the builds then run offline.
	cd $(IPSEC_WORK_DIR)/xkms-module && rm -f go.mod go.sum && \
		GOWORK=off go mod init ipsec-pkcs11-module >/dev/null 2>&1 && \
		GOWORK=off go get github.com/jeremyhahn/go-xkms@$(IPSEC_XKMS_VERSION) github.com/jeremyhahn/go-xkms/sdk/go@$(IPSEC_XKMS_VERSION) && \
		GOWORK=off GOFLAGS=-mod=mod go list -deps github.com/jeremyhahn/go-xkms/cmd/pkcs11-module >/dev/null
	@for a in $(IPSEC_ARCHES); do \
		mkdir -p $(IPSEC_WORK_DIR)/$$a && \
		docker run --rm --platform linux/$$a --user $$(id -u):$$(id -g) \
			-v $(abspath $(IPSEC_WORK_DIR)):/work -v $(GO_MODULE_CACHE):/go/pkg/mod:ro -w /work/xkms-module \
			-e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOWORK=off -e GOFLAGS=-mod=mod -e GOPROXY=off -e GOSUMDB=off -e CGO_ENABLED=1 \
			golang:1.27-bookworm \
			go build -buildmode=c-shared -trimpath -o /work/$$a/libxkms_pkcs11.so github.com/jeremyhahn/go-xkms/cmd/pkcs11-module || exit 1; \
		echo "$(IPSEC_WORK_DIR)/$$a/libxkms_pkcs11.so"; \
	done

.PHONY: ipsec-module-host
## ipsec-module-host: Export the glibc module-host root filesystems (p11-kit 0.26 server + the module) the p11-host apk packages, amd64 and arm64
ipsec-module-host: ipsec-pkcs11-module
	@for a in $(IPSEC_ARCHES); do \
		docker build --platform linux/$$a --build-context module=$(abspath $(IPSEC_WORK_DIR))/$$a \
			-t $(IPSEC_HOST_IMAGE):$$a build/docker/strongswan-builder/modulehost || exit 1; \
		cid=$$(docker create --platform linux/$$a $(IPSEC_HOST_IMAGE):$$a /bin/true) || exit 1; \
		docker export -o $(IPSEC_WORK_DIR)/modulehost-$$a.tar $$cid; rc=$$?; \
		docker rm $$cid >/dev/null; \
		[ $$rc -eq 0 ] || exit $$rc; \
		echo "$(IPSEC_WORK_DIR)/modulehost-$$a.tar"; \
	done

.PHONY: ipsec-arm64-vm
## ipsec-arm64-vm: Build the ipsec suite's aarch64 VM (kernel + initramfs) and the suite's test binary for arm64
ipsec-arm64-vm:
	@mkdir -p $(IPSEC_WORK_DIR)/vm
	docker build --output type=local,dest=$(IPSEC_WORK_DIR)/vm test/integration/ipsec/vm
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOWORK=off go test -c -tags "$(strip $(TEST_BUILD_TAGS))" \
		-o $(IPSEC_WORK_DIR)/ipsec-arm64.test ./test/integration/ipsec/

.PHONY: ipsec-test-inputs
## ipsec-test-inputs: Build every input of the ipsec integration suite from the strongSwan apks already built
ipsec-test-inputs: ipsec-peer-rootfs ipsec-arm64-vm

.PHONY: integration-test-ipsec
## integration-test-ipsec: IKEv2 through the go-xkms PKCS#11 module between musl charon peers, ESP asserted with ip xfrm, on amd64 and in an aarch64 VM (builds the apks first)
integration-test-ipsec: build-devcontainer strongswan-build ipsec-test-inputs
	$(call run-integration-suite,ipsec,$(IPSEC_SUITE_ENV))

.PHONY: integration-test-ipsec-only
## integration-test-ipsec-only: The ipsec suite against inputs already in work/ipsec (no rebuild)
integration-test-ipsec-only: build-devcontainer
	$(call run-integration-suite,ipsec,$(IPSEC_SUITE_ENV))


.PHONY: docker-builder-load-aarch64
docker-builder-load-aarch64:
	BUILDKIT_DEBUG=1 docker buildx build --load \
		--pull \
		--progress=plain \
	    --platform=linux/arm64 \
		-t $(APPNAME)-builder-$(DOCKER_BUILDER_BASE):arm64 \
		-f build/docker/$(APPNAME)-builder/$(DOCKER_BUILDER_DOCKERFILE) .


# Docker :: Trusted Platform Builder :: Remote
.PHONY: docker-builder-push
docker-builder-push:
	start_time=$$(date +%s); \
		docker buildx build --push \
			--memory=16g \
			--platform=linux/amd64,linux/arm64 \
			--progress=plain \
			-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-builder-alpine:latest \
			-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-builder-alpine:$(APP_VERSION) \
			-f build/docker/$(APPNAME)-builder/Dockerfile-alpine .; \
		docker buildx build --push \
			--memory=16g \
			--platform=linux/amd64,linux/arm64 \
			--progress=plain \
			-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-builder-debian:latest \
			-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-builder-debian:$(APP_VERSION) \
			-f build/docker/$(APPNAME)-builder/Dockerfile-debian .; \
	end_time=$$(date +%s); \
	elapsed_time=$$((end_time - start_time)); \
	hours=$$((elapsed_time/3600)); \
	minutes=$$(( (elapsed_time % 3600)/60 )); \
	seconds=$$((elapsed_time % 60)); \
	printf "${GREEN}Docker trusted-platform-builder execution time: %02d:%02d:%02d${NO_COLOR}\n" $$hours $$minutes $$seconds

# Docker :: Trusted Platform :: Local
.PHONY: docker-platform-load
docker-platform-load: 
	@start_time=$$(date +%s); \
		cd build/docker/$(APPNAME) && make -j20; \
	end_time=$$(date +%s); \
	elapsed_time=$$((end_time - start_time)); \
	hours=$$((elapsed_time/3600)); \
	minutes=$$(( (elapsed_time % 3600)/60 )); \
	seconds=$$((elapsed_time % 60)); \
	printf "Build execution time: %02d:%02d:%02d\n" $$hours $$minutes $$seconds

.PHONY: docker-platform-load-amd64
docker-platform-load-amd64:
	docker buildx build --load \
		--platform=linux/arm64 \
		--build-arg APPNAME=$(PLATFORMD) \
		-t $(APPNAME) \
		-f build/docker/$(APPNAME)/Dockerfile .


# Docker :: Trusted Platform :: Remote
.PHONY: docker-platform-push
docker-platform-push:
	docker buildx build --push \
		--platform=linux/amd64,linux/arm64 \
		--build-arg APPNAME=$(PLATFORMD) \
		-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-alpine:latest \
		-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-alpine:$(APP_VERSION) \
		-f build/docker/$(APPNAME)/Dockerfile-alpine .
	docker buildx build --push \
		--platform=linux/amd64,linux/arm64 \
		--build-arg APPNAME=$(PLATFORMD) \
		-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-debian:latest \
		-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-debian:$(APP_VERSION) \
		-f build/docker/$(APPNAME)/Dockerfile-alpine .


# Docker run targets; this is the interactive builder shell.
.PHONY: docker-run-debug
docker-run-debug: build-debug
	docker run -it --privileged \
	-v .:/mnt \
	-v /dev/bus/usb:/dev/bus/usb \
	trusted-platform-builder bash

.PHONY: docker-run-builder-with-usb
docker-run-builder-with-usb:
	docker run -it --rm --privileged \
		-v /dev/bus/usb:/dev/bus/usb \
		# -v /sys/devices/:/sys/devices/ \
		# -v /dev/hidraw4:/dev/hidraw4 \
		$(APPNAME)-builder \
		bash
		# /usr/local/bin/yubico-piv-tool -astatus

.PHONY: docker-run-yubico-piv-tool
docker-run-yubico-piv-tool:
	docker run -ti --rm \
		-v /dev/bus/usb:/dev/bus/usb \
		-v /sys/bus/usb/:/sys/bus/usb/ \
		-v /sys/devices/:/sys/devices/ \
		-v /dev/hidraw4:/dev/hidraw4 \
		--device /dev/usb:/dev/usb \
		--device /dev/bus/usb:/dev/bus/usb \
		--privileged \
		$(APPNAME)-builder \
		/usr/local/bin/yubico-piv-tool -astatus


# ISO: build ISOs with the in-CLI builder.
DISKIMAGE_TARGET      ?= rpi
DISKIMAGE_MODEL       ?= rpi4
DISKIMAGE_SIZE_MB     ?= 4096
DISKIMAGE_OUTPUT      ?= bin/trusted-platform-$(DISKIMAGE_TARGET).img
DISKIMAGE_BUILDER_IMG ?= trusted-platform-diskimage-builder
DISKIMAGE_HOST_ARCH   ?= $(ARCH)
DISKIMAGE_FLAGS       ?=
RPI_SDCARD            ?=
RPI_SDCARD_CONFIRM    ?=

.PHONY: docker-diskimage-builder-load
## docker-diskimage-builder-load: Build the host-platform assemble container image (tag :<hostarch>) for platformctl diskimage
docker-diskimage-builder-load:
	docker buildx build --load --platform=linux/$(DISKIMAGE_HOST_ARCH) -t $(DISKIMAGE_BUILDER_IMG):$(DISKIMAGE_HOST_ARCH) build/docker/diskimage-builder

.PHONY: image-rpi
## image-rpi: Build the Raspberry Pi SD-card image (DISKIMAGE_MODEL=rpi4, DISKIMAGE_OUTPUT=bin/trusted-platform-rpi.img)
image-rpi: build rpi-binaries
	$(PLATFORMCTL) diskimage create --target rpi --model $(DISKIMAGE_MODEL) --size $(DISKIMAGE_SIZE_MB) \
		--binaries-dir $(ARM64_BIN_DIR) --uboot-output-dir $(UBOOT_OUTPUT_DIR) --keys-dir $(UBOOT_KEYS_DIR) \
		--builder-image $(DISKIMAGE_BUILDER_IMG) --output $(DISKIMAGE_OUTPUT) $(DISKIMAGE_FLAGS)

.PHONY: image-rpi-qemu
## image-rpi-qemu: Build the QEMU virt stand-in image the diskimage integration suite boots
image-rpi-qemu: build rpi-binaries
	$(PLATFORMCTL) diskimage create --target qemu-virt --size $(DISKIMAGE_SIZE_MB) \
		--binaries-dir $(ARM64_BIN_DIR) --uboot-output-dir $(UBOOT_OUTPUT_DIR) --keys-dir $(UBOOT_KEYS_DIR) \
		--virt-kernel-output-dir $(VIRT_KERNEL_OUTPUT_DIR) \
		--builder-image $(DISKIMAGE_BUILDER_IMG) --output bin/trusted-platform-qemu-virt.img $(DISKIMAGE_FLAGS)

.PHONY: netboot-media
## netboot-media: Build the netboot media the bootstrap container serves (x86_64, Raspberry Pi and arm64 sets, Pi TFTP tree, signed arm64 iPXE) into NETBOOT_MEDIA_DIR; point bootstrap.yaml's deployer.netboot_media_dir at it
NETBOOT_MEDIA_DIR   ?= bin/netboot-media
NETBOOT_MEDIA_FLAGS ?=
netboot-media: build platform-initrd rpi-binaries ipxe-build
	$(PLATFORMCTL) diskimage netboot --output $(NETBOOT_MEDIA_DIR) \
		--x86-binaries-dir $(dir $(PLATFORMCTL)) --arm64-binaries-dir $(ARM64_BIN_DIR) \
		--uboot-output-dir $(UBOOT_OUTPUT_DIR) --virt-kernel-output-dir $(VIRT_KERNEL_OUTPUT_DIR) \
		--keys-dir $(UBOOT_KEYS_DIR) --ipxe $(IPXE_ARM64_EFI) \
		--builder-image $(DISKIMAGE_BUILDER_IMG) $(NETBOOT_MEDIA_FLAGS)

.PHONY: image-rpi-xz
## image-rpi-xz: Compress the Raspberry Pi image for release
image-rpi-xz: image-rpi
	xz -T0 -k -f $(DISKIMAGE_OUTPUT)

.PHONY: rpi-sdcard
## rpi-sdcard: Write the Raspberry Pi image to a removable device (RPI_SDCARD=/dev/sdX RPI_SDCARD_CONFIRM=yes); the only sudo target
rpi-sdcard:
	@test -n "$(RPI_SDCARD)" || { echo "RPI_SDCARD=/dev/sdX is required"; exit 1; }
	@test "$(RPI_SDCARD_CONFIRM)" = "yes" || { echo "refusing to write $(RPI_SDCARD) without RPI_SDCARD_CONFIRM=yes"; exit 1; }
	@test -b "$(RPI_SDCARD)" || { echo "$(RPI_SDCARD) is not a block device"; exit 1; }
	@root=$$(lsblk -no pkname $$(findmnt -no SOURCE /) 2>/dev/null); test "/dev/$$root" != "$(RPI_SDCARD)" || { echo "$(RPI_SDCARD) holds the running root filesystem"; exit 1; }
	@test "$$(lsblk -dno RM $(RPI_SDCARD))" = "1" || { echo "$(RPI_SDCARD) is not a removable device (lsblk RM=1)"; exit 1; }
	@test -f "$(DISKIMAGE_OUTPUT)" || { echo "$(DISKIMAGE_OUTPUT) not found (run make image-rpi)"; exit 1; }
	sudo dd if=$(DISKIMAGE_OUTPUT) of=$(RPI_SDCARD) bs=4M conv=fsync status=progress
	@echo "Image written to $(RPI_SDCARD)"

.PHONY: test-diskimage
## test-diskimage: Unit tests for pkg/diskimage and pkg/cli/commands/diskimage
test-diskimage:
	$(MAKE) test-pkg PKG="./pkg/diskimage/... ./pkg/cli/commands/diskimage/"

.PHONY: coverage-diskimage
## coverage-diskimage: Coverage for pkg/diskimage (mocks and tests excluded)
coverage-diskimage:
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) $(BUILD_TAGS_ARG) -coverprofile=$(COVERAGE_DIR)/diskimage.out ./pkg/diskimage/... ./pkg/cli/commands/diskimage/
	@grep -v -E '_test\.go|/mocks?/' $(COVERAGE_DIR)/diskimage.out > $(COVERAGE_DIR)/diskimage.filtered.out || true
	$(GOBIN)/go tool cover -func=$(COVERAGE_DIR)/diskimage.filtered.out | tail -1

.PHONY: bench-diskimage
## bench-diskimage: Benchmarks for pkg/diskimage
bench-diskimage:
	$(GOTEST) $(BUILD_TAGS_ARG) -run '^$$' -bench . -benchmem ./pkg/diskimage/...

.PHONY: test-qemu
## test-qemu: Unit tests for pkg/qemu (x86_64 golden and aarch64 profiles) and pkg/qemu/harness
test-qemu:
	$(MAKE) test-pkg PKG="./pkg/qemu/ ./pkg/qemu/harness/"

# The qemu-virt image and its U-Boot, as the integration suite sees them.
DISKIMAGE_QEMU_IMG   := bin/trusted-platform-qemu-virt.img
DISKIMAGE_UBOOT_QEMU := $(UBOOT_OUTPUT_DIR)/qemu_arm64/u-boot.bin
DISKIMAGE_UBOOT_RPI  := $(UBOOT_OUTPUT_DIR)/rpi_arm64/u-boot.bin

# The suite's inputs as the devcontainer sees them.
DISKIMAGE_SUITE_ENV := -e DISKIMAGE_IMAGE=/workspace/$(DISKIMAGE_QEMU_IMG) \
	-e DISKIMAGE_RPI_IMAGE=/workspace/$(DISKIMAGE_OUTPUT) \
	-e DISKIMAGE_UBOOT=/workspace/$(DISKIMAGE_UBOOT_QEMU) \
	-e DISKIMAGE_WORK_DIR=/workspace/work/diskimage-integration

.PHONY: integration-test-diskimage
## integration-test-diskimage: Boot the factory image under QEMU aarch64 + swtpm in the devcontainer (builds the images first; 30-60 min under TCG)
integration-test-diskimage: build-devcontainer image-rpi image-rpi-qemu
	$(call run-integration-suite,diskimage,$(DISKIMAGE_SUITE_ENV))

.PHONY: integration-test-diskimage-only
## integration-test-diskimage-only: The diskimage suite against images already in bin/ (no rebuild)
integration-test-diskimage-only: build-devcontainer
	$(call run-integration-suite,diskimage,$(DISKIMAGE_SUITE_ENV))

# The aarch64 network-boot suite: QEMU virt from the qemu_arm64 U-Boot on the PXE test bridge.
NETBOOT_ALPINE_BRANCH ?= v3.22
NETBOOT_ALPINE_MIRROR ?= https://dl-cdn.alpinelinux.org/alpine
NETBOOT_INPUT_DIR     ?= bin/netboot/aarch64
NETBOOT_INPUTS        := $(addprefix $(NETBOOT_INPUT_DIR)/,vmlinuz-lts initramfs-lts modloop-lts)

$(NETBOOT_INPUT_DIR)/%:
	@mkdir -p $(NETBOOT_INPUT_DIR)
	curl -fsSL -o $@.part $(NETBOOT_ALPINE_MIRROR)/$(NETBOOT_ALPINE_BRANCH)/releases/aarch64/netboot/$* && mv $@.part $@

.PHONY: netboot-inputs
## netboot-inputs: Fetch the Alpine aarch64 netboot kernel, initramfs and modloop the netboot suite boots
netboot-inputs: $(NETBOOT_INPUTS)

NETBOOT_SUITE_ENV := -v $(abspath $(UBOOT_KEYS_DIR)):/keys:ro \
	-e NETBOOT_UBOOT=/workspace/$(DISKIMAGE_UBOOT_QEMU) \
	-e NETBOOT_IPXE=/workspace/$(IPXE_ARM64_EFI) \
	-e NETBOOT_KEYS_DIR=/keys \
	-e NETBOOT_KERNEL=/workspace/$(NETBOOT_INPUT_DIR)/vmlinuz-lts \
	-e NETBOOT_INITRD=/workspace/$(NETBOOT_INPUT_DIR)/initramfs-lts \
	-e NETBOOT_MODLOOP=/workspace/$(NETBOOT_INPUT_DIR)/modloop-lts \
	-e NETBOOT_ALPINE_REPO=$(NETBOOT_ALPINE_MIRROR)/$(NETBOOT_ALPINE_BRANCH)/main \
	-e NETBOOT_ALPINE_MIRROR=$(NETBOOT_ALPINE_MIRROR) \
	-e NETBOOT_ALPINE_VERSION=$(patsubst v%,%,$(NETBOOT_ALPINE_BRANCH)) \
	-e NETBOOT_UBOOT_DIR=/workspace/$(UBOOT_OUTPUT_DIR) \
	-e NETBOOT_RPI_APK_DIR=/workspace/bin/netboot/rpi-apks \
	-e NETBOOT_WORK_DIR=/workspace/work/netboot-integration

.PHONY: integration-test-netboot
## integration-test-netboot: The network-boot suite in the devcontainer — QEMU aarch64 from the platform's U-Boot through the PXE server, and the Raspberry Pi EEPROM stage against the emulator (builds U-Boot and iPXE and fetches the inputs first)
integration-test-netboot: build-devcontainer uboot-build ipxe-build netboot-inputs
	$(call run-integration-suite,netboot,$(NETBOOT_SUITE_ENV))

.PHONY: integration-test-netboot-only
## integration-test-netboot-only: The netboot suite against the U-Boot and inputs already built
integration-test-netboot-only: build-devcontainer
	$(call run-integration-suite,netboot,$(NETBOOT_SUITE_ENV))

# The NAT64 suite runs in a VM with its own kernel.
NAT64_VM_DIR   ?= bin/nat64-vm
NAT64_VM_IMAGE := go-trusted-platform-nat64-vm
NAT64_VM_RUN   ?= TestJoolDriver|TestNAT64Datapath

.PHONY: nat64-vm
## nat64-vm: Build the NAT64 test VM (Alpine linux-lts + jool-modules-lts + Open vSwitch) into bin/nat64-vm
nat64-vm:
	@mkdir -p $(NAT64_VM_DIR)
	docker build -t $(NAT64_VM_IMAGE) build/docker/nat64-vm/
	@cid=$$(docker create $(NAT64_VM_IMAGE) /none) && \
		docker cp $$cid:/vmlinuz $(NAT64_VM_DIR)/vmlinuz && \
		docker cp $$cid:/rootfs.cpio.gz $(NAT64_VM_DIR)/rootfs.cpio.gz; \
		rc=$$?; docker rm $$cid >/dev/null; exit $$rc

.PHONY: nat64-vm-suite
## nat64-vm-suite: Build the static NAT64 guest suite (test/integration/sdn with the nat64vm tag)
nat64-vm-suite:
	@mkdir -p $(NAT64_VM_DIR)
	CGO_ENABLED=0 GOWORK=off go test -c -tags '$(strip $(TEST_BUILD_TAGS)) nat64vm' \
		-o $(NAT64_VM_DIR)/sdn-nat64.test ./test/integration/sdn/

NAT64_SUITE_ENV := -e NAT64_VM_KERNEL=/workspace/$(NAT64_VM_DIR)/vmlinuz \
	-e NAT64_VM_ROOTFS=/workspace/$(NAT64_VM_DIR)/rootfs.cpio.gz \
	-e NAT64_VM_SUITE=/workspace/$(NAT64_VM_DIR)/sdn-nat64.test \
	-e 'NAT64_VM_RUN=$(NAT64_VM_RUN)'

.PHONY: integration-test-nat64
## integration-test-nat64: The NAT64 suite in an Alpine VM under QEMU/KVM in the devcontainer: the Jool driver against the real module and the datapath end to end (builds the VM and the suite first)
integration-test-nat64: build-devcontainer nat64-vm nat64-vm-suite
	$(call run-integration-suite,nat64,$(NAT64_SUITE_ENV))

.PHONY: integration-test-diskimage-shell
## integration-test-diskimage-shell: Interactive devcontainer shell with the factory-image inputs in the environment
integration-test-diskimage-shell: build-devcontainer
	@docker run --rm -it --privileged \
		--name go-trusted-platform-diskimage-shell \
		-v $(PWD):$(SOURCES_BASE)/go-trusted-platform \
		-v $(PWD):/workspace \
		-v $(GO_MODULE_CACHE):/go/pkg/mod \
		-w /workspace \
		-e GOWORK=off \
		$(DISKIMAGE_SUITE_ENV) \
		$(DEVCONTAINER_IMAGE) \
		bash

# The arm64 userspace suite: aarch64 platformd on musl against a swtpm in an arm64 Alpine container.
DISKIMAGE_USERSPACE_IMG := trusted-platform-alpine-swtpm:arm64
DISKIMAGE_USERSPACE_BIN := bin/aarch64/diskimage-userspace.test

# swtpm runs on the host with its state bind-mounted, since it cannot create its sockets under qemu-user.
DISKIMAGE_USERSPACE_SWTPM_DIR := $(PWD)/work/userspace-swtpm

.PHONY: integration-test-diskimage-userspace
## integration-test-diskimage-userspace: aarch64 platformd + swtpm userspace suite in an arm64 Alpine container (no boot; needs swtpm on the host)
integration-test-diskimage-userspace: rpi-binaries
	@command -v swtpm >/dev/null || { echo "ERROR: swtpm is required on the host (apt-get install swtpm / apk add swtpm)"; exit 1; }
	@echo "Building the arm64 userspace suite..."
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBIN)/go test -c -tags "integration $(BUILD_TAGS)" \
		-o $(DISKIMAGE_USERSPACE_BIN) ./test/integration/diskimage/userspace/
	@echo "Building $(DISKIMAGE_USERSPACE_IMG)..."
	@docker build --platform linux/arm64 -t $(DISKIMAGE_USERSPACE_IMG) \
		-f build/docker/trusted-platform/Dockerfile-alpine-swtpm-arm64 build/docker/trusted-platform/
	@echo "Starting the host swtpm..."
	@if [ -f $(DISKIMAGE_USERSPACE_SWTPM_DIR)/swtpm.pid ]; then kill $$(cat $(DISKIMAGE_USERSPACE_SWTPM_DIR)/swtpm.pid) 2>/dev/null || true; fi
	@rm -rf $(DISKIMAGE_USERSPACE_SWTPM_DIR) && mkdir -p $(DISKIMAGE_USERSPACE_SWTPM_DIR)
	@# An EK certificate, as a manufactured TPM (and the Pi's SLB9670)
	@# carries one. swtpm_setup issues it through swtpm_localca, whose
	@# default state directory is root-owned, so a private local CA under
	@# the suite's own directory is configured for this run.
	@mkdir -p $(DISKIMAGE_USERSPACE_SWTPM_DIR)/localca
	@printf 'create_certs_tool = swtpm_localca\ncreate_certs_tool_config = %s/localca.conf\ncreate_certs_tool_options = %s/localca.options\n' \
		$(DISKIMAGE_USERSPACE_SWTPM_DIR) $(DISKIMAGE_USERSPACE_SWTPM_DIR) > $(DISKIMAGE_USERSPACE_SWTPM_DIR)/swtpm_setup.conf
	@printf 'statedir = %s/localca\nsigningkey = %s/localca/signkey.pem\nissuercert = %s/localca/issuercert.pem\ncertserial = %s/localca/certserial\n' \
		$(DISKIMAGE_USERSPACE_SWTPM_DIR) $(DISKIMAGE_USERSPACE_SWTPM_DIR) $(DISKIMAGE_USERSPACE_SWTPM_DIR) $(DISKIMAGE_USERSPACE_SWTPM_DIR) > $(DISKIMAGE_USERSPACE_SWTPM_DIR)/localca.conf
	@printf -- '--platform-manufacturer TrustedPlatform\n--platform-version 1\n--platform-model userspace-suite\n' > $(DISKIMAGE_USERSPACE_SWTPM_DIR)/localca.options
	@swtpm_setup --tpm2 --tpmstate $(DISKIMAGE_USERSPACE_SWTPM_DIR) --config $(DISKIMAGE_USERSPACE_SWTPM_DIR)/swtpm_setup.conf \
		--create-ek-cert --create-platform-cert --pcr-banks sha256 --overwrite >/dev/null
	@swtpm socket --tpm2 --tpmstate dir=$(DISKIMAGE_USERSPACE_SWTPM_DIR) \
		--server type=unixio,path=$(DISKIMAGE_USERSPACE_SWTPM_DIR)/swtpm.sock \
		--ctrl type=unixio,path=$(DISKIMAGE_USERSPACE_SWTPM_DIR)/swtpm.sock.ctrl \
		--flags not-need-init,startup-clear --log level=1 \
		--pid file=$(DISKIMAGE_USERSPACE_SWTPM_DIR)/swtpm.pid --daemon
	@for i in $$(seq 1 30); do test -S $(DISKIMAGE_USERSPACE_SWTPM_DIR)/swtpm.sock && break; sleep 1; done
	@test -S $(DISKIMAGE_USERSPACE_SWTPM_DIR)/swtpm.sock || { echo "FATAL: the host swtpm did not open its socket"; exit 1; }
	@chmod 777 $(DISKIMAGE_USERSPACE_SWTPM_DIR) $(DISKIMAGE_USERSPACE_SWTPM_DIR)/swtpm.sock $(DISKIMAGE_USERSPACE_SWTPM_DIR)/swtpm.sock.ctrl
	@echo "Running the arm64 userspace suite..."
	@rc=0; docker run --rm --privileged --platform linux/arm64 \
		--name go-trusted-platform-diskimage-userspace \
		-v $(PWD)/bin/aarch64:/platform/bin:ro \
		-v $(PWD)/test/integration/diskimage/userspace/config.yaml:/platform/config.yaml:ro \
		-v $(DISKIMAGE_USERSPACE_SWTPM_DIR):/trusted-platform/volume/swtpm \
		-e PLATFORMD_BIN=/platform/bin/platformd \
		-e PLATFORMCTL_BIN=/platform/bin/platformctl \
		-e PLATFORM_CONFIG=/platform/config.yaml \
		-e SWTPM_SOCKET=/trusted-platform/volume/swtpm/swtpm.sock \
		$(DISKIMAGE_USERSPACE_IMG) \
		/platform/bin/diskimage-userspace.test -test.v -test.count=1 -test.timeout 20m || rc=$$?; \
		kill $$(cat $(DISKIMAGE_USERSPACE_SWTPM_DIR)/swtpm.pid) 2>/dev/null || true; exit $$rc

.PHONY: isos
isos:
	@start_time=$$(date +%s); \
		bin/platformctl iso create --output bin/$(ISO_NAME); \
	end_time=$$(date +%s); \
	elapsed_time=$$((end_time - start_time)); \
	hours=$$((elapsed_time/3600)); \
	minutes=$$(( (elapsed_time % 3600)/60 )); \
	seconds=$$((elapsed_time % 60)); \
	printf "Build execution time: %02d:%02d:%02d\n" $$hours $$minutes $$seconds


# Browser targets trusting the QEMU server's CA: make chrome, make firefox, or make browser to auto-detect.
BROWSER_SERVER_URL    ?= https://server.example.com:8443
BROWSER_CA_BUNDLE_URL ?= $(BROWSER_SERVER_URL)/api/v1/ca/bootstrap
BROWSER_PROFILE_DIR   ?= /tmp/trusted-platform-browser

.PHONY: browser
browser:
	@if which google-chrome-stable >/dev/null 2>&1 || which google-chrome >/dev/null 2>&1 || which chromium-browser >/dev/null 2>&1; then \
		$(MAKE) chrome; \
	elif which firefox >/dev/null 2>&1; then \
		$(MAKE) firefox; \
	else \
		echo "No supported browser found (install Chrome or Firefox)"; \
		exit 1; \
	fi

.PHONY: chrome
chrome:
	@echo "Fetching CA bundle from $(BROWSER_CA_BUNDLE_URL)..."
	@mkdir -p $(BROWSER_PROFILE_DIR)/chrome
	@curl -sk $(BROWSER_CA_BUNDLE_URL) > $(BROWSER_PROFILE_DIR)/ca-bundle.pem
	@# Import certs into Chrome's NSS database at ~/.pki/nssdb/
	@mkdir -p $(HOME)/.pki/nssdb
	@if [ ! -f $(HOME)/.pki/nssdb/cert9.db ]; then \
		certutil -d sql:$(HOME)/.pki/nssdb -N --empty-password; \
	fi
	@cd $(BROWSER_PROFILE_DIR) && csplit -f cert- -z ca-bundle.pem '/-----BEGIN CERTIFICATE-----/' '{*}' 2>/dev/null; \
	for f in $(BROWSER_PROFILE_DIR)/cert-*; do \
		CN=$$(openssl x509 -in "$$f" -noout -subject -nameopt multiline 2>/dev/null | grep commonName | sed 's/.*= //'); \
		certutil -d sql:$(HOME)/.pki/nssdb -A -t "CT,C,C" -n "$$CN" -i "$$f" 2>/dev/null; \
		echo "  Imported: $$CN"; \
	done; \
	rm -f $(BROWSER_PROFILE_DIR)/cert-*
	@echo "Certs imported to ~/.pki/nssdb/ (quit Chrome fully and relaunch if already open)"
	@echo "Launching Chrome with trusted CA profile..."
	@CHROME=$$(which google-chrome-stable 2>/dev/null || which google-chrome 2>/dev/null || which chromium-browser 2>/dev/null); \
	"$$CHROME" \
		--user-data-dir=$(BROWSER_PROFILE_DIR)/chrome \
		--no-first-run \
		--disable-default-apps \
		$(BROWSER_SERVER_URL)/ &

.PHONY: firefox
firefox:
	@echo "Fetching CA bundle from $(BROWSER_CA_BUNDLE_URL)..."
	@mkdir -p $(BROWSER_PROFILE_DIR)/firefox-certs /etc/firefox/policies 2>/dev/null || true
	@curl -sk $(BROWSER_CA_BUNDLE_URL) > $(BROWSER_PROFILE_DIR)/ca-bundle.pem
	@# Split PEM bundle into individual DER certs for Firefox policy
	@cd $(BROWSER_PROFILE_DIR) && csplit -f cert- -z ca-bundle.pem '/-----BEGIN CERTIFICATE-----/' '{*}' 2>/dev/null; \
	for f in $(BROWSER_PROFILE_DIR)/cert-*; do \
		CN=$$(openssl x509 -in "$$f" -noout -subject -nameopt multiline 2>/dev/null | grep commonName | sed 's/.*= //'); \
		SAFE=$$(echo "$$CN" | tr ' /' '_-'); \
		cp "$$f" $(BROWSER_PROFILE_DIR)/firefox-certs/$$SAFE.pem; \
		echo "  Prepared: $$CN"; \
	done; \
	rm -f $(BROWSER_PROFILE_DIR)/cert-*
	@# Generate Firefox policies.json pointing to fetched certs
	@echo '{"policies":{"Certificates":{"ImportEnterpriseRoots":true,"Install":[' > $(BROWSER_PROFILE_DIR)/firefox-policies.json
	@FIRST=1; for f in $(BROWSER_PROFILE_DIR)/firefox-certs/*.pem; do \
		[ $$FIRST -eq 1 ] && FIRST=0 || printf ',' >> $(BROWSER_PROFILE_DIR)/firefox-policies.json; \
		printf '"%s"' "$$f" >> $(BROWSER_PROFILE_DIR)/firefox-policies.json; \
	done
	@echo ']}}}' >> $(BROWSER_PROFILE_DIR)/firefox-policies.json
	@sudo mkdir -p /etc/firefox/policies
	@sudo cp $(BROWSER_PROFILE_DIR)/firefox-policies.json /etc/firefox/policies/policies.json
	@echo "Launching Firefox with trusted CA policy..."
	@firefox $(BROWSER_SERVER_URL)/ &


# TPM 2.0
.PHONY: clear-auth
clear-auth:
	sudo tpm2_changeauth -c e -p test
	sudo tpm2_changeauth -c o -p test
	sudo tpm2_changeauth -c l -p test

.PHONY: config
config:
	mkdir -p pkg/$(PLATFORM_DIR)/etc/ pkg/$(PLATFORM_DIR)/softhsm2
	cp configs/platform/$(CONFIG_YAML) pkg/config.yaml
	cp configs/softhsm.conf pkg/trusted-data/etc/softhsm.conf

# Testenv Enrollment Integration Tests
.PHONY: integration-test-testenv-enrollment
## integration-test-testenv-enrollment: Run TestEnrollmentIntegration in the devcontainer
integration-test-testenv-enrollment: build-devcontainer
	$(call run-integration-suite,testenv-enrollment,-e INTEGRATION_TEST_SERVER_ISO -e INTEGRATION_TEST_CLIENT_ISO)

.PHONY: integration-test-testenv-enrollment-clean
integration-test-testenv-enrollment-clean:
	@echo "Cleaning testenv enrollment test artifacts..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "ERROR: Cleanup requires root privileges"; \
		echo "Run with: sudo make integration-test-testenv-enrollment-clean"; \
		exit 1; \
	fi
	-rm -rf test-integration-enrollment/
	-ip link delete tp-br 2>/dev/null || true
	-ip link delete tap-tp-server 2>/dev/null || true
	-ip link delete tap-tp-client 2>/dev/null || true
	-iptables -t nat -D POSTROUTING -s 10.99.99.0/28 -j MASQUERADE 2>/dev/null || true
	@echo "Cleanup complete"


# Build all shipped binaries: platformd and platformctl (build), plus platform-initrd
.PHONY: build-all
build-all: build platform-initrd

.PHONY: build-all-debug
build-all-debug: build-debug platform-initrd-debug

.PHONY: build-all-static
build-all-static: build-all
	@echo "build-all-static target is deprecated. Use 'make build-all' instead (now produces static binaries by default)."

# Every binary for ISO and deployment, static: platformd, platformctl and platform-initrd.
.PHONY: binaries
binaries: build platform-initrd
	@echo "Built all static binaries:"
	@echo "  platformd:       $$(du -h $(PLATFORMD) | cut -f1) (daemon)"
	@echo "  platformctl:     $$(du -h $(PLATFORMCTL) | cut -f1) (CLI)"
	@echo "  platform-initrd: $$(du -h $(PLATFORM_INITRD) | cut -f1) (initramfs)"

.PHONY: binaries-static
binaries-static: binaries
	@echo "binaries-static target is deprecated. Use 'make binaries' instead (now produces static binaries by default)."

# Every binary a linux/arm64 node needs, pure Go, into $(ARM64_BIN_DIR).
.PHONY: rpi-binaries
## rpi-binaries: Cross-compile every linux/arm64 binary (platformd, platformctl, platformctl-static, platform-initrd, gatewayd) into bin/aarch64
rpi-binaries: build-arm64 platform-initrd-arm64 build-gatewayd-arm64
	@echo "Built all ARM64 static binaries in $(ARM64_BIN_DIR):"
	@echo "  platformd:         $$(du -h $(PLATFORMD_ARM64) | cut -f1) (daemon)"
	@echo "  platformctl:       $$(du -h $(PLATFORMCTL_ARM64) | cut -f1) (CLI)"
	@echo "  platformctl-static: $$(du -h $(PLATFORMCTL_STATIC_ARM64) | cut -f1) (CLI, ISO sibling)"
	@echo "  platform-initrd:   $$(du -h $(PLATFORM_INITRD_ARM64) | cut -f1) (initramfs)"
	@echo "  gatewayd:          $$(du -h $(GATEWAYD_ARM64) | cut -f1) (edge gateway)"

.PHONY: binaries-arm64
binaries-arm64: rpi-binaries

.PHONY: binaries-arm64-static
binaries-arm64-static: binaries-arm64
	@echo "binaries-arm64-static target is deprecated. Use 'make rpi-binaries' instead (a CGO_ENABLED=0 cross build is already static)."

# Test the REST API
.PHONY: test-api
test-api:
	# tag-independent
	cd pkg/api/rest && go test -v


# Builds never resolve through a workspace.
export GOWORK=off

# deps-latest runs before compiling in a consumer repository.

.PHONY: deps-latest

deps-latest:
	@GOWORK=off sh -c ' \
	SELF=$$(go list -m); \
	for m in $$(go list -m -f "{{if not .Indirect}}{{.Path}}{{end}}" all 2>/dev/null | grep "^github.com/jeremyhahn/" | grep -vx "$$SELF"); do \
	  case "$$(go list -m -f "{{if .Replace}}{{.Replace.Path}}{{end}}" "$$m" 2>/dev/null)" in .*|/*) continue;; esac; \
	  V=$$(go list -m -versions "$$m" 2>/dev/null | tr " " "\n" | tail -1); \
	  if [ -n "$$V" ] && [ "$$V" != "$$m" ]; then go get "$$m@$$V" || exit 1; fi; \
	done; go mod tidy'

# deps-check fails when a direct require is behind its latest version without a comment naming the reason.
.PHONY: deps-check
## deps-check: Fail when a dependency is behind its latest version without a go.mod reason comment
deps-check:
	@$(GO) run ./scripts/depscheck -go $(GO) . sdk/go

# release-alpha template v2.4.0: `make release-alpha VERSION=vX.Y.Z-alpha` cuts an alpha from main.
REPO_NAME        ?= go-trusted-platform
AGENT_GIT        ?= agent-git.sh
RELEASE_REMOTE   ?= origin
LOCKSTEP_MODULES := sdk/go
include build/make/release-alpha.mk

# The template's version guard is a recipe line, which `make -n` prints instead of running.
.PHONY: release-alpha-version
release-alpha: release-alpha-version
release-alpha-version:
	+@test -n "$$REL_VERSION" || { echo 'ERROR: state the version explicitly: make release-alpha VERSION=vX.Y.Z-alpha (release-versioning.md decides patch/minor/major — the recipe refuses to guess)'; exit 1; }
