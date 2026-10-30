TARGET_OS               := linux
TARGET_ARCH             := $(shell uname -m)

# =============================================================================
# Build Configuration Variables
# =============================================================================
#
# This section defines all WITH_* variables for fine-grained build customization.
# Variables are organized by project/feature area and use ?= for override support.
#
# Usage:
#   make build WITH_AWS=1 WITH_RAFT=1
#   make integration-test WITH_RAFT=1
#   WITH_AWS=1 WITH_GCP=1 make build
#
# =============================================================================

# -----------------------------------------------------------------------------
# Cloud Provider Group Variables (enables ALL features for a provider)
# These cascade down to enable individual project features
# -----------------------------------------------------------------------------
WITH_AWS                ?= 0    # Enable ALL AWS features (KMS, S3, etc.) across all projects
WITH_GCP                ?= 0    # Enable ALL GCP features (KMS, GCS, etc.) across all projects
WITH_AZURE              ?= 0    # Enable ALL Azure features (KeyVault, Blob, etc.) across all projects

# -----------------------------------------------------------------------------
# go-quicbaas Build Variables
# See: go-quicbaas/Makefile for full documentation
# -----------------------------------------------------------------------------

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

# -----------------------------------------------------------------------------
# go-xkms Build Variables
# See: go-xkms/Makefile for full documentation
# -----------------------------------------------------------------------------

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

# Cloud Compute Providers (individual control). Local compute (QEMU VMs +
# containers) is always compiled; only the cloud providers are tag-gated.
WITH_AWS_COMPUTE        ?= 0    # AWS EC2 NitroTPM compute orchestrator
WITH_GCP_COMPUTE        ?= 0    # Google Compute Engine (Shielded/Confidential VM) orchestrator
WITH_AZURE_COMPUTE      ?= 0    # Azure Trusted Launch VM orchestrator

# -----------------------------------------------------------------------------
# go-objstore Build Variables
# Object storage backend selection
# -----------------------------------------------------------------------------
WITH_OBJSTORE_LOCAL     ?= 1    # Local filesystem storage (always enabled)
WITH_OBJSTORE_S3        ?= 0    # AWS S3 storage
WITH_OBJSTORE_MINIO     ?= 0    # MinIO storage
WITH_OBJSTORE_GCS       ?= 0    # Google Cloud Storage
WITH_OBJSTORE_AZURE     ?= 0    # Azure Blob Storage

# -----------------------------------------------------------------------------
# go-trusted-platform Build Variables
# Platform-specific features
# -----------------------------------------------------------------------------
WITH_WEB                ?= 0    # Embed web frontend into binary (off by default for dev speed; fallback copies public_html.tar.gz into ISO)
WITH_DESKTOP            ?= 0    # Build desktop GUI (requires Wails v2)
WITH_P2P                ?= 0    # P2P/libp2p networking support
WITH_FIPS               ?= 0    # FIPS 140-3 build tag (selects the FIPS crypto implementations at compile time; pair with GODEBUG=fips140=only)

# -----------------------------------------------------------------------------
# Codec Build Variables
# Serialization format support
# -----------------------------------------------------------------------------
WITH_CODEC_JSON         ?= 1    # JSON codec
WITH_CODEC_MSGPACK      ?= 1    # MessagePack codec
WITH_CODEC_CBOR         ?= 1    # CBOR codec
WITH_CODEC_YAML         ?= 0    # YAML codec
WITH_CODEC_TOML         ?= 0    # TOML codec
WITH_CODEC_BSON         ?= 0    # BSON codec
WITH_CODEC_PROTOBUF     ?= 0    # Protocol Buffers codec

# =============================================================================
# Cloud Provider Group Variable Expansion
# When WITH_AWS=1, enable all AWS features across all projects
# =============================================================================
ifeq ($(strip $(WITH_AWS)),1)
    WITH_AWS_KMS        := 1
    WITH_OBJSTORE_S3    := 1
    WITH_AWS_COMPUTE    := 1
endif
ifeq ($(strip $(WITH_GCP)),1)
    WITH_GCP_KMS        := 1
    WITH_OBJSTORE_GCS   := 1
    WITH_GCP_COMPUTE    := 1
endif
ifeq ($(strip $(WITH_AZURE)),1)
    WITH_AZURE_KV       := 1
    WITH_OBJSTORE_AZURE := 1
    WITH_AZURE_COMPUTE  := 1
endif

# =============================================================================
# Feature Dependency Validation
# =============================================================================
ifeq ($(strip $(WITH_RAG)),1)
    ifneq ($(strip $(WITH_VECTOR)),1)
        $(error WITH_RAG=1 requires WITH_VECTOR=1)
    endif
endif

# =============================================================================
# BUILD_TAGS Construction
# Dynamically assembled based on WITH_* variables
# Note: Using $(strip) to handle trailing whitespace from inline comments
#
# Core feature tags that the platform binary REQUIRES at runtime are
# included unconditionally. Setting them to opt-in caused platformd to
# ship without IAM, which then hard-failed at startup with "IAM service
# not enabled". If a deployment wants to drop one of these, override by
# building with -tags directly; the WITH_* env vars remain for legacy
# control over truly optional features.
# =============================================================================
# gms_pure_go: the go-mysql-server dependency (indirect, via quicbaas,
# bumped 2026-08-12) gates its regex package on `cgo || gms_pure_go`.
# All platform binaries build with CGO_ENABLED=0 (Alpine/musl policy),
# so the pure-Go implementation must be selected explicitly or the
# build fails with "build constraints exclude all Go files" in
# go-mysql-server/internal/regex.
BUILD_TAGS := iam rest quic mcp cluster gms_pure_go

# go-quicbaas tags.
#
# Cross-layer tag coordination: quicbaas features that ride on a qrdb
# engine must enable the corresponding qrdb tag (qrdb's own tag names,
# per the qrdb build-tag matrix). quicbaas's handlers are untagged and
# compile against qrdb's stub seams, so omitting the qrdb tag does NOT
# fail the build — the feature silently returns feature-disabled at
# runtime. The pairings below keep that from ever happening.
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

# qrdb optional features (default OFF for the platform — lean build).
# WITH_QRDB_SQL enables qrdb's SQL query engine (pkg/sql over
# go-mysql-server; the gms_pure_go tag above keeps it CGO-free).
# The MySQL/PostgreSQL wire frontends are engines over that SQL layer,
# so enabling either implies qrdb_sql.
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

# FIPS. Additive on purpose: the FIPS suite must compile and test the SAME
# configuration the normal suite does, with only the crypto implementation
# swapped. Overriding BUILD_TAGS on the command line instead would discard
# every `BUILD_TAGS +=` above it — command-line variables win over makefile
# assignments — and silently test a build with no codecs, no raft and no
# frost. That is exactly how the nightly FIPS job spent weeks reporting
# `no codec available for encoding` as if it were a FIPS finding.
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

# GO_BUILD_TAGS (#960). ci-template v1.21 passes the repository's tag set to
# lint, build, coverage, security and integration-test as a space-separated
# make variable (handbook devcontainer.md §6). It is appended here, after
# every `+=` above and before any variable is derived from BUILD_TAGS, so each
# consumer — print-build-tags, every `go build`/`go test`, TEST_BUILD_TAGS and
# the integration runner — reads it from this one place. Like WITH_FIPS it is
# additive: it never replaces the derived set. Empty or unset changes nothing.
#
# The analysers that do not read BUILD_TAGS (golangci-lint, gosec,
# govulncheck) take GO_BUILD_TAGS alone, comma separated, through
# GO_BUILD_TAGS_CSV. `make check-go-build-tags` (run by `make test`) fails if
# any of those targets drops it.
comma                   := ,
empty                   :=
space                   := $(empty) $(empty)
GO_BUILD_TAGS_CSV       := $(subst $(space),$(comma),$(strip $(GO_BUILD_TAGS)))
ifneq ($(GO_BUILD_TAGS_CSV),)
    BUILD_TAGS += $(GO_BUILD_TAGS)
endif

# =============================================================================
# Build Tag Flags
# =============================================================================
# TAG-INDEPENDENT TARGETS (#390). Some `go test` invocations below deliberately
# omit -tags, and that is verified per package rather than assumed:
# `go test -list '.*' <pkg>` returns an IDENTICAL test set with and without
# $(BUILD_TAGS) for pkg/crypto/{aesgcm,argon2}, pkg/store/datastore and its
# kvstore, pkg/compute, pkg/bmc, pkg/cli/commands/bmc, pkg/api/rest, pkg/ntp,
# and pkg/sdn/{vxlan,bgp,gateway,ipam,dhcp,openflow}. Measured 2026-09-04.
# Those sites are marked `# tag-independent` so the omission reads as a
# decision someone checked, not an oversight nobody noticed.
#
# pkg/storage/quicbaas is NOT in that set: 573 tests visible untagged against
# 672 tagged, and a full untagged run passes green over 99 fewer tests than the
# tagged one. Its targets pass $(BUILD_TAGS) explicitly for that reason.

BUILD_TAGS_ARG          := $(if $(strip $(BUILD_TAGS)),-tags '$(strip $(BUILD_TAGS))',)

# Integration tests always need codec tags for QUIC protocol support.
# The go-codec library uses build tags to compile real codecs vs stubs.
INTEGRATION_CODEC_TAGS  := codec_msgpack codec_json codec_cbor
# Integration builds carry the vector service (the WITH_VECTOR=1 tags), and
# pkg/storage/quicbaas.TestConfig enables it in exactly such a build. The
# factory's Vector assertion runs as a unit test; add these tags through
# GO_BUILD_TAGS to run it against a real vector store.
INTEGRATION_VECTOR_TAGS := vector qrdb_vector
TEST_BUILD_TAGS         := integration $(INTEGRATION_CODEC_TAGS) $(INTEGRATION_VECTOR_TAGS) $(strip $(BUILD_TAGS))
TEST_BUILD_TAGS_ARG     := -tags '$(strip $(TEST_BUILD_TAGS))'

# Web embed directory
WEB_EMBED_DIR           := pkg/webserver/embed/dist

# Desktop frontend directories
DESKTOP_FRONTEND_SRC    := cmd/platformctl/frontend
DESKTOP_FRONTEND_DIST   := cmd/platformctl/frontend/dist

# The go command on PATH, or empty. A host without Go (CI's integration legs
# build the integration image on a runner that has none, #1119) takes the
# host's GOOS and GOARCH from uname and GOBIN from GO_IMAGE's install path, so
# a target that only drives docker parses without go.
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
PLATFORM_INITRD         ?= bin/platform-initrd
GATEWAYD                ?= bin/gatewayd
DEPLOYER_PIN            ?= bin/deployer-pin

# Cross-compiled arm64 binaries land under their own directory so a native
# x86-64 build never overwrites them (and vice versa).
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
# gatewayd carries its own version vars (pkg/sdn/gateway/commands) so it
# never links the platformd composition root pkg/app (see
# pkg/arch/gatewayguard_test.go).
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
# DOMAIN has no default: it is a deployment value. webservice-verify-tls
# requires it, and SWAGGER_HOST follows it (unset leaves the OpenAPI host
# empty, so the docs resolve against whichever host serves them).
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

# ISO_NAME is the artifact name produced by `platformctl iso create`. The
# legacy Docker-based iso-hwtpm / iso-swtpm targets and their
# trusted-platform-iso-builder image were removed in favor of the
# in-CLI builder; see `bin/platformctl iso create --help`.
ISO_NAME                    ?= trusted-platform.iso

UID                         := $(shell id -u)
GID                         := $(shell id -g)

# Build and coverage directories
BUILD_DIR                   := build
COVERAGE_DIR                := $(BUILD_DIR)/coverage
# Pinned Go tools are built from their own tools modules under build/tools-src/
# (one go.mod + go.sum per tool, outside the main module's graph and outside
# `./...`), and each pin lives in that go.mod and only there. The Makefile reads
# the version back out of it, so there is no second list to keep in step — a
# class of defect this repo has hit repeatedly. ci.yml installs the linters by
# calling `make install-golangci-lint` / `make lint`, so CI and a developer
# machine cannot drift either.
#
# They are built with `go build -C <tools module> -mod=readonly`, NEVER with
# `go install <pkg>@<version>` (#584): the @version form makes the go command
# look up the module's deprecation notice, a module query that a lane's
# GOPROXY=off refuses even when every module is already in the cache. A build
# from a module with a committed go.sum makes no query at all, and node-prep
# fills the cache from every tracked go.mod, so the tools' graphs reach every
# node. pkg/arch/maketools_test.go fails on a pinned `go install` here.
#
# To move a pin, with network: in the tool's module run
#   go get -tool <tool package>@<version> && go mod tidy
# and commit go.mod + go.sum (trivy fs scans them, so keep their dependencies
# patched as the main module's are).
#
# $(call tools-module-version,<tools module dir>,<module path>) is the version
# <tools module dir>/go.mod requires of <module path>. It is read with make's
# own $(file), so parsing the Makefile starts no process and needs no network.
tools-module-version = $(patsubst $(2)@%,%,$(filter $(2)@%,$(subst $(2) v,$(2)@v,$(file < $(1)/go.mod))))

# golangci-lint
#
# PINNED (devops.md §9, documented). History, because the reason changed:
#
#   v2.12.2 was the pin while v2.13.0 (2026-08-19) shipped honnef.co/go/tools
#   v0.8.0-rc.1, whose nilness pass panicked ("unhandled builtin recover",
#   crashed on sentry-go) — a red gate with zero findings. The stated unpin
#   condition was "a non-rc staticcheck that passes on main".
#
#   MOVED to v2.13.2 on 2026-09-22, when this module adopted Go 1.27.0 with
#   go-quicbaas v0.11.0-alpha. v2.12.2 bundles honnef.co/go/tools v0.7.0, which
#   cannot parse the Go 1.27 standard library: it PANICS in its IR builder
#   ("buildir: unexpected expr: *ast.KeyValueExpr", package internal/poll)
#   rather than reporting findings, so `make lint` died with a stack trace and
#   no result. Staying on v2.12.2 stopped being an option the moment the
#   language version moved.
#
#   v2.13.2 ships a non-rc staticcheck, which satisfies the original unpin
#   condition, and is the version go-quicbaas pins for the same Go 1.27
#   adoption — one version across the two repos that share this toolchain.
#
#   MOVED to v2.14.0 on 2026-10-07 (#744): the CI runner image carries the
#   upstream latest of every analysis tool and the jobs assert the baked tool
#   matches this pin. Never pin below the latest release.
#
#   The tools module requires exactly golangci-lint's own released go.mod, so
#   the binary links the same dependency versions `go install ...@v2.14.0` did.
GOLANGCI_LINT_SRC           := build/tools-src/golangci-lint
GOLANGCI_LINT_VERSION       := $(call tools-module-version,$(GOLANGCI_LINT_SRC),github.com/golangci/golangci-lint/v2)

# actionlint checks .github/workflows/ and is pinned and built the same way as
# golangci-lint. `make lint` runs it so a broken workflow fails here, not in CI.
# Its tools module is actionlint's released go.mod with golang.org/x/net raised
# to the main module's v0.60.0 (CVE-2026-78669; the same move #775 made for gosec)
# and golang.org/x/sys to the v0.48.0 that x/net version requires.
ACTIONLINT_SRC              := build/tools-src/actionlint
ACTIONLINT_VERSION          := $(call tools-module-version,$(ACTIONLINT_SRC),github.com/rhysd/actionlint)

# gosec is pinned and built with THIS module's toolchain, for the same reason as
# golangci-lint: a gosec built with an older Go cannot type-check a module that
# declares a newer `go` line, so every package reports "type errors" and the
# scan exits non-zero with an empty report. v2.29.0 is the newest gosec v2
# release (and the only one) in the module cache.
#
# gosec is built from its own tools module, $(GOSEC_SRC), NOT with
# `go install ...@$(GOSEC_VERSION)`: that resolves against gosec's own go.mod,
# whose golang.org/x/tools is too old to read Go 1.27 export data, so every
# package still reports type errors. The tools module requires gosec (a `tool`
# directive) and a current x/tools (v0.51.0), and commits its go.sum. The
# version is that module's gosec requirement; the main module's go.mod is
# untouched.
GOSEC_SRC                   := build/tools-src/gosec
GOSEC_VERSION               := $(call tools-module-version,$(GOSEC_SRC),github.com/securego/gosec/v2)

# An empty version would build into an unstamped directory and print a blank
# pin; stop at parse time instead, naming the variable.
$(foreach v,GOLANGCI_LINT_VERSION ACTIONLINT_VERSION GOSEC_VERSION,$(if $($(v)),,$(error $(v) is empty: its tools module's go.mod under build/tools-src does not require the tool)))
GOSEC_DIR                   := $(BUILD_DIR)/tools/gosec-$(GOSEC_VERSION)
GOSEC                       := $(GOSEC_DIR)/gosec

# golangci-lint v2 has NO default timeout ("Disabled by default"); this is the
# only wall-clock bound on the run, and 15m was calibrated on an idle box. It is
# process wall-clock from the moment the binary starts — queueing for a runner
# does not count, but waiting on golangci-lint's own instance lock does (`lint`
# passes --allow-serial-runners, so a concurrent invocation waits for the lock
# instead of exiting with "parallel golangci-lint is running", #309). Measured
# 2026-09-05 on the shared capacity-3 fleet (#426), linter phase only, from
# "Running linters" to "issues.":
#     406s  #405 rerun (job 49321)   green
#     506s  #410      (job 49204)   green
#    1137s  #409      (job 49195)   "0 issues." then "Timeout exceeded", at 15m
#    1150s  #405      (job 49110)   same
# The two failures had finished analysing — 0 issues printed — and tripped the
# deadline on the way out; the code was never the problem. 2.8x spread between
# the quietest and the most contended run; 45m is ~2.3x the worst observed, so a
# further doubling of contention still lands. The CI lint job carries a
# timeout-minutes backstop above this so a genuinely hung linter still fails
# with a job timeout rather than running unbounded. Not --allow-parallel-runners
# (runs would share one cache and contend for CPU), and not a rerun policy.
GOLANGCI_LINT_TIMEOUT       ?= 45m

# Built from source with `go build`, NOT downloaded prebuilt. That is the whole point:
# building from source uses this module's own toolchain, so the linter can never
# be older than the Go version go.mod targets. A prebuilt release binary is built
# with whatever Go its release used, which is how `make lint` came to fail with
# "the Go language version (go1.25) used to build golangci-lint is lower than the
# targeted Go version" (#297).
#
# The directory is stamped with the version, so changing the pin above installs
# the new one and leaves the old binary unused rather than silently running it.
# That also makes the "is it already installed?" check exact instead of a guess.
GOLANGCI_LINT_DIR           := $(BUILD_DIR)/tools/golangci-lint-$(GOLANGCI_LINT_VERSION)
GOLANGCI_LINT               := $(GOLANGCI_LINT_DIR)/golangci-lint
ACTIONLINT_DIR              := $(BUILD_DIR)/tools/actionlint-$(ACTIONLINT_VERSION)
ACTIONLINT                  := $(ACTIONLINT_DIR)/actionlint
# Per-checkout analysis cache. golangci-lint's default is one shared
# ~/.cache/golangci-lint for every checkout on the machine, and cached issues
# carry the ABSOLUTE path of the tree that produced them. Two checkouts with
# byte-identical package content therefore share cache entries, and a finding
# can be reported against a path in a different worktree — including one that
# has since been deleted, whose files can no longer be read to apply the
# //nolint directives that suppressed it (#365). Absolute, because the
# value is consumed by a tool that stores absolute paths.
#
# Exported rather than set on the one recipe that needs it, for the same reason
# as `export GOWORK=off` below: a second golangci-lint invocation added later
# must not have to remember. Prefixing the invocation would leave the next one
# silently back on the shared cache.
export GOLANGCI_LINT_CACHE  := $(abspath $(BUILD_DIR)/tools/golangci-lint-cache)

COVERAGE_FILE               := $(COVERAGE_DIR)/coverage.out
COVERAGE_HTML               := $(COVERAGE_DIR)/coverage.html

# Test configuration
GO                          := go
GOTEST                      := $(GO) test
GOVET                       := $(GO) vet
GOFMT                       := gofmt
TEST_FLAGS                  := -v -race
# COVERAGE_THRESHOLD is enforced as a HARD gate by `make coverage-report`
# (exit 1 on miss). Kept at 90 to match the documented repo-wide floor; if a
# CI run reports below this, ratchet down to the measured floor and raise over time.
COVERAGE_THRESHOLD          := 90

# Security scanning configuration
# Gosec exclusions with rationale:
#   G103: unsafe package - required for TPM and low-level crypto operations
#   G104: unhandled errors - false positives on deferred Close() calls
#   G115: integer overflow - false positives on type conversions with bounds checks
#   G304: file path from variable - required for config-driven file operations
#   G401: MD5/SHA1 - required for certificate thumbprints, PKCS standards
#   G407: hardcoded nonce - false positive, nonces are random not hardcoded
#   G505: crypto/sha1 import - required for PKCS standards, WebAuthn
# How many packages gosec analyzes at once. Each worker type-checks its
# package, so memory grows with it; CI's make security step passes 2 to keep
# the stage under its 16g container limit (#1178).
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

# Emit the assembled tag list so a caller that must invoke `go` directly
# (the nightly FIPS build, which compiles ./... rather than the binaries)
# builds the same configuration the make targets do. Deliberately placed
# AFTER `default:` — the first non-special target is what bare `make` runs.
.PHONY: print-build-tags
## help: List the documented make targets (every `## target: description` line)
.PHONY: help
help:
	@grep -h '^## [A-Za-z0-9_.-]*:' $(MAKEFILE_LIST) | sed 's/^## //' | sort

## print-build-tags: Print the derived build-tag set (use this, never a copied list)
#
# The authoritative tag set for any run not fully delegated to make. Prefer
# `make test-pkg PKG=...` where it fits; reach for this only when you need the
# tags for something make does not wrap, e.g.
#   go vet -tags "$(shell make -s print-build-tags)" ./pkg/...
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

# binfmt registers qemu-user for arm64 (and arm) with the F flag, which every
# --platform linux/arm64 container on this host runs through: the strongSwan
# and Raspberry Pi builds, the assemble container, the arm64 userspace suite.
# The image is pinned by digest. multiarch/qemu-user-static, used before,
# ships qemu 7.2 (2023), under which Alpine 3.22's gcc 14 segfaults at random
# (measured 2026-10-01: cc1 and collect2 SIGSEGV in two strongSwan arm64
# builds); tonistiigi/binfmt at this digest is qemu 10.2.3. The old handlers
# are removed first, because an existing registration is never replaced.
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
# `$(WEB_EMBED_DIR)/*` DELIBERATELY does not match dotfiles, and that is
# now load-bearing rather than incidental. Since #256 the directory's only
# tracked entry is .gitkeep, and `//go:embed all:dist` needs a file present
# or a clean checkout will not compile under `platform_web`. The default
# glob leaves .gitkeep alone; `find -delete`, an added `.[!.]*`, or running
# this under `shopt -s dotglob` would delete a TRACKED file, so every
# working tree shows a deletion after a build and a fresh clone fails to
# build. Verified: `sh -c 'rm -rf d/*'` keeps .gitkeep; the same command
# under `bash -O dotglob` removes it. Do not "tidy" this.
	@rm -rf $(WEB_EMBED_DIR)/*
# Same dotfile semantics, facing the other way: a dotfile emitted by the
# web build would silently not be copied, and so not be embedded. Nothing
# in web/out is a dotfile today; if that changes, this glob is why the
# asset went missing.
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

# Compile every package in BOTH modules, in BOTH tag configurations, emitting no
# binaries. `build-no-web` only compiles what the three binaries import, so on
# its own it covers neither.
#
# Both configurations, because neither is a superset of the other. The tagged
# build is the shipped one, and it alone reaches the tagged-only code. But this
# tree also carries files selected by the ABSENCE of a tag — pkg/api/daemon's
# iam_service_stub.go and cluster_service_stub.go are `//go:build !iam` and
# `!cluster`, and !awscompute, !azurecompute, !fips, !gcpcompute, !key_safety,
# !platform_p2p and !platform_web exist too. Every one of those files is
# invisible to the tagged build and compiled only by the untagged one. Dropping
# either pass leaves a live surface unchecked.
#
# The tag set comes from BUILD_TAGS rather than a hand-copied list because it is
# assembled in two stages — a literal `:=` line plus the conditional `+=`
# appends below it — and copying only the `:=` line silently drops every codec.
#
# sdk/go is a separate module and gets the same tag set: it carries no build
# constraints in non-test files at all, so tagged and untagged select an
# identical file set there and passing the tags costs nothing. Should that stop
# being true, this target is where the two modules' tag sets would diverge.
#
# NOT covered here, deliberately: platform-initrd. It is a separate compilation
# unit with its own INITRD_BUILD_TAGS and CGO_ENABLED=0, so it is `make
# platform-initrd`, built as the binary it ships as — not a package compile.
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

# Native local build (builds both platformd and platformctl)
# Produces static binaries with embedded web frontend
# Set WITH_WEB=0 to skip web frontend embedding (default is enabled)
# Set WITH_P2P=1 to include P2P/libp2p support in gatewayd
.PHONY: build
# Alpine/musl targets require CGO=0 (glibc-linked static still imports
# __vfprintf_chk and other symbols that fail on musl). osusergo+netgo
# replace the CGO-based user/net lookups with pure-Go fallbacks.
build: _web-embed-prepare
	@mkdir -p bin
	CGO_ENABLED=0 $(GOBIN)/go build -tags "osusergo netgo $(BUILD_TAGS)" -v -o $(PLATFORMD) --ldflags '-w -s ${LDFLAGS}' ./cmd/platformd
	CGO_ENABLED=0 $(GOBIN)/go build -tags "osusergo netgo $(BUILD_TAGS)" -v -o $(PLATFORMCTL) --ldflags '-w -s ${LDFLAGS}' ./cmd/platformctl
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

# Cross-compile ARM 64-bit: a pure-Go build (CGO_ENABLED=0, same tag set as the
# native `build` target), so no cross toolchain is required and the result is a
# statically linked ELF. Output goes to $(ARM64_BIN_DIR), never bin/, so it
# cannot clobber a native build. platformctl-static is the sibling name that
# `platformctl iso create` (pkg/iso/customize.go) looks for next to platformd;
# with CGO disabled it is byte-identical to platformctl, so it is a copy.
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


# ==============================================================================
# Platform-initrd Build Targets (minimal initramfs binary)
# ==============================================================================
# platform-initrd contains ONLY boot and recovery commands for initramfs.
# Firstboot functionality has been moved to platformctl (runs after switch_root).
# Target binary size: ~22MB (heavy deps excluded via package separation)
# Uses CGO_ENABLED=0 for static linking without C dependencies
# Build tags: initrd,osusergo,netgo for pure Go implementations

# Initrd build tags - minimal dependencies for initramfs binary
# osusergo,netgo: Pure Go implementations without cgo
# local: Required for go-objstore local storage backend registration
# Note: Heavy dependencies (firstboot, app, installer) excluded via package separation
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

# Cross-compile ARM 64-bit for initrd: same pure-Go build as `platform-initrd`,
# written to $(ARM64_BIN_DIR) so it never overwrites the native binary.
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


# ==============================================================================
# Gateway Daemon Build Targets (standalone SDN gateway binary)
# ==============================================================================
# gatewayd is a standalone gateway daemon supporting three operational modes:
#   - Overlay: VXLAN tunneling for east-west VM/container traffic (EVPN Type-2/3/5)
#   - Edge: IoT device onboarding, DHT bootstrap, NAT traversal
#   - Transit: Announce platform IPv4/IPv6 blocks to ISPs/fabric
#
# Build without P2P: make build-gatewayd
# Build with P2P:    make build-gatewayd WITH_P2P=1

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

# Cross-compile ARM 64-bit for gatewayd: a pure-Go build (CGO_ENABLED=0 with
# osusergo/netgo, exactly as the native `build` target links gatewayd), written
# to $(ARM64_BIN_DIR) so it never overwrites the native binary.
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

# ==============================================================================
# Deployer Pin Build Target (SSH host-key pin provisioning tool)
# ==============================================================================
# deployer-pin is the only supported way to populate the per-pin envelope store
# that the bootstrap deployer, physical switch management and the EVPN fabric
# driver read. Those SSH stacks are fail-closed — an empty known_hosts_path is
# rejected and there is no trust-on-first-use fallback — so a fleet bring-up
# cannot get past the deploy phase without this binary.
#
# It links neither pkg/app nor pkg/sdn/gateway/commands, so the -X version
# stamps in LDFLAGS resolve to no symbol and the linker drops them; LDFLAGS is
# still passed so the flags stay uniform with the sibling binary targets.
# Also built by `make build` and `make build-no-web`.

.PHONY: build-deployer-pin
build-deployer-pin:
	@mkdir -p bin
	@echo "Building deployer-pin (SSH host-key pin tool - static)..."
	CGO_ENABLED=0 $(GOBIN)/go build -tags "osusergo netgo $(BUILD_TAGS)" \
		--ldflags '-w -s ${LDFLAGS}' \
		-o $(DEPLOYER_PIN) ./cmd/deployer-pin
	@echo "Binary size: $$(du -h $(DEPLOYER_PIN) | cut -f1)"
# ==============================================================================

# Build the public_html directory using devcontainer
# This target uses docker to ensure consistent builds regardless of host environment
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


# =============================================================================
# Frontend (Next.js) - monorepo web/ directory
# =============================================================================

.PHONY: web-install
web-install:
	@echo "[Web] Installing npm dependencies..."
	cd $(WEB_SRC) && npm install

# web depends on trusted-platform-sdk via `file:../sdk/javascript`, whose
# package.json entry points all resolve into sdk/javascript/dist. That directory
# is build output and gitignored, so on a fresh checkout it does not exist and
# the Next.js build fails to resolve the module. Build the SDK first, exactly as
# _web-embed-prepare does — otherwise the target only works on a machine whose
# stale dist happens to be lying around.
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

# vitest over web/src/**/*.test.ts(x): hooks, stores, contexts in jsdom, no
# server. Playwright (web-test) owns the browser flows.
.PHONY: web-test-unit
web-test-unit:
	@echo "[Web] Running unit tests (vitest)..."
	cd $(WEB_SRC) && npm run test:unit

.PHONY: web-test-ui
web-test-ui:
	@echo "[Web] Running Playwright E2E tests with UI..."
	cd $(WEB_SRC) && npm run test:e2e:ui

# WebAuthn E2E tests — pass FRONTEND_URL and HEADED via env vars
# Examples:
#   make web-test-webauthn
#   make web-test-webauthn FRONTEND_URL=https://server.example.com:8443
#   make web-test-webauthn FRONTEND_URL=https://server.example.com:8443 HEADED=1
.PHONY: web-test-webauthn
web-test-webauthn:
	cd $(WEB_SRC) && $(MAKE) test-webauthn

# CI-shaped web targets (#396). web-install/web-sdk-build above use
# `npm install` for a developer's incremental loop; these use `npm ci` so the
# run is reproducible from the lockfile — the same reasoning as test-sdk-js.
#
# web-deps is the prerequisite the checks share, and the order matters: web/
# typechecks against sdk/javascript's BUILT dist/ (every package.json entry
# point of trusted-platform-sdk resolves into it), and dist/ is gitignored. On
# a fresh checkout `tsc` without the SDK build reports hundreds of
# missing-module errors that say nothing about the console — a clean runner
# measured 335 that way against a controlled 8.
.PHONY: web-deps
web-deps:
	@echo "[Web] Installing from lockfiles and building trusted-platform-sdk..."
	cd sdk/javascript && npm ci && npm run build
	cd $(WEB_SRC) && npm ci

# eslint only. Typecheck was folded into this target before #396; it is now
# web-typecheck so CI can gate the two independently.
.PHONY: web-lint
web-lint:
	@echo "[Web] Running ESLint..."
	cd $(WEB_SRC) && npm run lint

.PHONY: web-typecheck
web-typecheck:
	@echo "[Web] Running TypeScript checks..."
	cd $(WEB_SRC) && npm run typecheck

# `next build` only — web-build above also copies the output into the tracked
# public_html/ and tars it, which is a release step, not a check.
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

# Tests
# Note: pkg/tpm2, pkg/ca, and pkg/store/keystore have been migrated to external libraries:
# - TPM2: github.com/jeremyhahn/go-xkms/pkg/tpm2
# - CA: github.com/jeremyhahn/go-trusted-ca/pkg/ca
# - Keystore: github.com/jeremyhahn/go-xkms/pkg/backend/*
# TEST_SKIP quarantines individual tests, with a reason and a date. It is not a
# place to park a failure nobody has diagnosed — every entry names the conflict
# and what would retire it.
#
# 2026-08-14 — the five assertions below all pin the Supermicro UEFI virtual-CD
# alias to "UefiCd" and all fail, because pkg/quirks/registry.go sets
# UEFICDAlias = "UefiUsbCd". The two carry opposite claims about the same
# hardware: the tests come from 5030627 (2026-05-21, "fix(bmc,ipxe,iso): ...
# UefiCd>UefiUsbCd"), while registry.go's comment says the opposite was
# "Verified on X10SDV-TP8F: ... targeting UefiCd points the boot override at
# the empty class and the node skips to PXE/disk". The registry value is the
# later of the two but landed in a4a45f0 (2026-08-13), a "checkpoint working
# tree" commit that did not touch the tests, so its provenance is weaker than
# its comment suggests. Only a boot on an X10 settles it. Skipped rather than
# deleted or "fixed" so the contradiction stays visible; retire this once the
# hardware answer is recorded in the registry.
TEST_SKIP := TestPickBootSourceOverrideTarget_X10WithCDDVDAlias|TestPickBootSourceOverrideTarget_X10PrefersVendorUEFIOverUSBCD|TestX10SDVBootMediaType|TestSupermicroManufacturerWideBootMediaType|TestResolveVeloCloudEDGE840

.PHONY: test
test: check-insecure-tls check-go-build-tags
	@echo "Running all unit tests..."
	go test -tags "$(BUILD_TAGS)" -v -skip "$(TEST_SKIP)" $$(go list ./pkg/... ./cmd/... 2>/dev/null | grep -v -E "$(TEST_EXCLUDE)") $(TEST_UNIT_PKGS)

.PHONY: test-fips
## test-fips: FIPS 140-3 suite: build ./... and run `make test`, both with the fips tag under GODEBUG=fips140=only
#
# The ONE definition of the FIPS job: ci.yml (push to main, workflow_dispatch)
# and nightly.yml (workflow_dispatch) both run this target, so the two cannot
# drift apart. BOTH halves matter and they do different jobs:
#   WITH_FIPS=1 (the `fips` tag) selects the FIPS implementations at COMPILE
#       time, so MD5/SHA-1 are not linked in at all;
#   GODEBUG=fips140=only enforces at RUNTIME, and is what proves the
#       compile-time gate was complete.
# STRICT mode, not `fips140=on` (ratified 2026-08-17): `on` loads the Go
# Cryptographic Module but still PERMITS non-approved algorithms, so the suite
# would report green while a regulated path used prohibited cryptography.
# WITH_FIPS=1, never BUILD_TAGS="...": a command-line BUILD_TAGS replaces the
# Makefile's tag list instead of appending to it.
# CUSTOMIZE (ruling 125): the unit tests' output also goes to $(FIPS_LOG) and,
# when they fail, scripts/foreignfailures -job fips is the target's verdict. It
# passes only when every failure is a listed panic of $(FIPS_FOREIGN_BASELINE)
# (exact test, message and stack frame, nothing else failing) AND every other
# top-level test of each panicked package, rerun by explicit name with the same
# environment and tags, passes. A rerun round that fails only by another
# listed panic excludes that test too and runs the rest again, at most one
# round per row of the package. It fails closed on anything else
# (docs/test/integration.md "The FIPS baseline").
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

.PHONY: test-pkg
## test-pkg: Run unit tests for ONE package with the derived tag set, e.g. make test-pkg PKG=./pkg/api/daemon/
#
# Use this instead of typing `go test -tags "..."` by hand. BUILD_TAGS is
# assembled in two stages — the `:=` literal plus the conditional `+=` appends
# below it — so a hand-copied tag list silently drops every codec, and the run
# then fails with "no codec available for encoding" in a package that is
# actually fine. That failure reads as a regression in whatever you just
# changed, which is how the nightly FIPS job spent weeks reporting it as a FIPS
# finding. Deriving the tags here means nobody has to know that.
#
# TESTFLAGS passes anything else through, split on whitespace only:
#   make test-pkg PKG=./pkg/api/daemon/ TESTFLAGS='-run TestFoo -v'
#   make test-pkg PKG=./pkg/api/daemon/ TESTFLAGS='-run TestFoo|TestBar -race'
# The recipe single-quotes TESTFLAGS into a shell variable and expands it
# unquoted with globbing off, so `|`, `*`, `;` and `'` reach go test verbatim
# instead of being read as shell syntax. Do not quote inside TESTFLAGS: a
# pattern cannot contain spaces (go test -run patterns never need them).
test-pkg:
	@if [ -z "$(strip $(PKG))" ]; then \
		echo "$(RED)$(BOLD)PKG is required$(RESET)"; \
		echo "  usage: make test-pkg PKG=./pkg/api/daemon/"; \
		echo "         make test-pkg PKG=./pkg/api/daemon/ TESTFLAGS='-run TestFoo -v'"; \
		exit 2; \
	fi
	set -f; testflags='$(subst ','\'',$(TESTFLAGS))'; \
	go test -tags "$(BUILD_TAGS)" -skip "$(TEST_SKIP)" $$testflags $(PKG)

# Tagged for the reason test-pkg above documents. Untagged, the codec registry
# is empty and every encode fails with "no codec available for encoding";
# sdk/go/transport/quic was this module's instance -- 13 tests, one error, none
# of them about the code under test (#344).
.PHONY: test-sdk-go
## test-sdk-go: Run Go SDK unit tests (sdk/go module)
test-sdk-go:
	@echo "Running Go SDK unit tests..."
	cd sdk/go && go test -tags "$(BUILD_TAGS)" ./...

.PHONY: sdk-consumer-check
## sdk-consumer-check: Build sdk/go from a throwaway consumer module, without the root module (#840)
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

# test-ca: Migrated to go-trusted-ca - run tests there instead
# test-tpm: Migrated to go-xkms - run tests there instead

.PHONY: test-crypto
test-crypto:
	# tag-independent
	cd pkg/crypto/aesgcm && go test -v
	# tag-independent
	cd pkg/crypto/argon2 && go test -v

.PHONY: test-store
test-store: test-store-datastore

# test-store-pkcs11: Migrated to go-xkms/pkg/backend/pkcs11
# test-store-tpm2: Migrated to go-xkms/pkg/tpm2/store

.PHONY: test-store-datastore
test-store-datastore:
	cd pkg/store/datastore && \
		# tag-independent
		go test -v
	cd pkg/store/datastore/kvstore && \
		# tag-independent
		go test -v

# QuicBaaS Unit Tests (fast, uses mock storage - no real Raft needed)
# Runs: *_unit_test.go tests + config, error, mock_storage tests
# These tests run in ~0.1s and cover adapter.go, DAOs, and utilities
.PHONY: test-quicbaas
test-quicbaas:
	@echo "Running QuicBaaS unit tests (fast, no Raft)..."
	go test -v -count=1 -tags "$(BUILD_TAGS)" -run "Test.*_Mock|^TestMockStorage|^TestErr|^TestDefault|^TestConfig|^TestConsistency|^TestParse|^TestGetFree|^TestAllErrors" ./pkg/storage/quicbaas/...

# QuicBaaS Unit Tests with Coverage (fast tests only - no real Raft)
# Target: ~62% coverage (client.go and factory.go require Raft for testing)
.PHONY: test-quicbaas-coverage
test-quicbaas-coverage:
	@echo "Running QuicBaaS unit tests with coverage (fast, no Raft)..."
	@echo "Note: client.go and factory.go (0%) require Raft - tested via test-quicbaas-coverage-full"
	go test -count=1 -tags "$(BUILD_TAGS)" -run "Test.*_Mock|^TestMockStorage|^TestErr|^TestDefault|^TestConfig|^TestConsistency|^TestParse|^TestGetFree|^TestAllErrors" -coverprofile=/tmp/quicbaas.cover ./pkg/storage/quicbaas/...
	go tool cover -func=/tmp/quicbaas.cover | tail -1

# QuicBaaS Full Coverage (includes Raft tests - runs serially, takes 3+ minutes)
# This includes client.go and factory.go tests that need real Raft consensus
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

# AVR firmware attestation tests
#
# No hardware and no device. The tests drive a fake link through the real
# trusted-firmware codec, so they run as fast as any other unit test and
# modify nothing on the host.
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

## test-cloud-compute-aws: Run AWS EC2 NitroTPM live cloud tests (opt-in, real AWS)
## Requires AWS credentials in the environment (COMPUTE_AWS_REGION, COMPUTE_AWS_AMI,
## COMPUTE_AWS_INSTANCE_TYPE and standard AWS_* credentials). Mirrors go-objstore's
## cloud_integration,awss3 precedent. This test launches real EC2 instances and
## incurs cost; it is never run by the default suite.
.PHONY: test-cloud-compute-aws
test-cloud-compute-aws:
	@echo "$(CYAN)→ Running AWS NitroTPM compute cloud tests (real AWS, may incur cost)$(RESET)"
	COMPUTE_AWS_LIVE=1 $(GOBIN)/go test -v -tags 'cloud_integration awscompute' \
		-count=1 -timeout 20m ./pkg/compute/aws -run TestAWSCompute_RealCloud

## test-cloud-compute-gcp: Run GCP Shielded VM live cloud tests (opt-in, real GCP)
## Requires GCP application default credentials and COMPUTE_GCP_PROJECT,
## COMPUTE_GCP_ZONE, COMPUTE_GCP_MACHINE_TYPE, COMPUTE_GCP_IMAGE (optionally
## COMPUTE_GCP_NETWORK, COMPUTE_GCP_SUBNETWORK, COMPUTE_GCP_CREDENTIALS). This
## test launches real Compute Engine instances and incurs cost; it is never run
## by the default suite.
.PHONY: test-cloud-compute-gcp
test-cloud-compute-gcp:
	@echo "$(CYAN)→ Running GCP Shielded VM compute cloud tests (real GCP, may incur cost)$(RESET)"
	COMPUTE_GCP_LIVE=1 $(GOBIN)/go test -v -tags 'cloud_integration gcpcompute' \
		-count=1 -timeout 20m ./pkg/compute/gcp -run TestGCPCompute_RealCloud

## test-cloud-compute-azure: Run Azure Trusted Launch live cloud tests (opt-in, real Azure)
## Requires Azure default credentials and COMPUTE_AZURE_SUBSCRIPTION,
## COMPUTE_AZURE_RESOURCE_GROUP, COMPUTE_AZURE_LOCATION, COMPUTE_AZURE_VM_SIZE,
## COMPUTE_AZURE_IMAGE (optionally COMPUTE_AZURE_TENANT). This test launches real
## Virtual Machines and incurs cost; it is never run by the default suite.
.PHONY: test-cloud-compute-azure
test-cloud-compute-azure:
	@echo "$(CYAN)→ Running Azure Trusted Launch compute cloud tests (real Azure, may incur cost)$(RESET)"
	COMPUTE_AZURE_LIVE=1 $(GOBIN)/go test -v -tags 'cloud_integration azurecompute' \
		-count=1 -timeout 25m ./pkg/compute/azure -run TestAzureCompute_RealCloud

## integration-test-compute-aws: Run AWS EC2 lifecycle integration test against the Floci emulator (no cloud creds)
## Brings up Floci (floci/floci:latest, endpoint-URL drop-in AWS emulator) on :4566 via docker
## compose, runs the AWS orchestrator EC2 instance lifecycle test (create/start/stop/get/list/
## terminate) through the real aws-sdk-go-v2 client, then tears the emulator down. Floci emulates
## the EC2 instance lifecycle ONLY — no EBS snapshots, no NitroTPM, no GCP/Azure. Full-surface and
## attestation coverage lives in the faked-client unit tests and the -real targets below.
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

## integration-test-compute-aws-real: Run the AWS EC2 NitroTPM live-cloud test against REAL AWS (creds-gated)
## Exercises the FULL orchestrator including real NitroTPM 2.0 endorsement-key attestation and EBS
## snapshots — the only true attestation validation. Provisions REAL, BILLABLE EC2 resources and
## cleans them up (Delete + DeleteSnapshot via t.Cleanup). Never runs in the default suite; never
## t.Skips — fails loudly if required env is missing.
## Required env: COMPUTE_AWS_REGION, COMPUTE_AWS_AMI (TpmSupport=v2.0), COMPUTE_AWS_INSTANCE_TYPE
##   (a Nitro type), optionally COMPUTE_AWS_SUBNET, plus AWS credentials (AWS_* or an IAM role).
.PHONY: integration-test-compute-aws-real
integration-test-compute-aws-real:
	@echo "$(CYAN)$(BOLD)→ Running AWS EC2 NitroTPM live-cloud test (REAL AWS, provisions BILLABLE resources)...$(RESET)"
	COMPUTE_AWS_LIVE=1 $(GOBIN)/go test -v \
		-tags 'cloud_integration awscompute $(INTEGRATION_CODEC_TAGS)' \
		-count=1 -timeout 20m ./pkg/compute/aws -run TestAWSCompute_RealCloud
	@echo "$(GREEN)✓ AWS EC2 NitroTPM live-cloud test complete$(RESET)"

## integration-test-compute-gcp-real: Run the GCP Shielded VM live-cloud test against REAL GCP (creds-gated)
## Exercises the FULL orchestrator including real Shielded-VM vTPM attestation and disk snapshots.
## Provisions REAL, BILLABLE Compute Engine resources and cleans them up (Delete + DeleteSnapshot via
## t.Cleanup). Never t.Skips — fails loudly if required env is missing.
## Required env: COMPUTE_GCP_PROJECT, COMPUTE_GCP_ZONE, COMPUTE_GCP_MACHINE_TYPE (Shielded-capable),
##   COMPUTE_GCP_IMAGE (UEFI/Shielded), optionally COMPUTE_GCP_NETWORK, COMPUTE_GCP_SUBNETWORK,
##   COMPUTE_GCP_CREDENTIALS, plus Google application default credentials.
.PHONY: integration-test-compute-gcp-real
integration-test-compute-gcp-real:
	@echo "$(CYAN)$(BOLD)→ Running GCP Shielded VM live-cloud test (REAL GCP, provisions BILLABLE resources)...$(RESET)"
	COMPUTE_GCP_LIVE=1 $(GOBIN)/go test -v \
		-tags 'cloud_integration gcpcompute $(INTEGRATION_CODEC_TAGS)' \
		-count=1 -timeout 20m ./pkg/compute/gcp -run TestGCPCompute_RealCloud
	@echo "$(GREEN)✓ GCP Shielded VM live-cloud test complete$(RESET)"

## integration-test-compute-azure-real: Run the Azure Trusted Launch live-cloud test against REAL Azure (creds-gated)
## Exercises the FULL orchestrator including real Trusted-Launch vTPM attestation and disk snapshots.
## Provisions REAL, BILLABLE Virtual Machine resources and cleans them up (Delete + DeleteSnapshot via
## t.Cleanup). Never t.Skips — fails loudly if required env is missing.
## Required env: COMPUTE_AZURE_SUBSCRIPTION, COMPUTE_AZURE_RESOURCE_GROUP, COMPUTE_AZURE_LOCATION,
##   COMPUTE_AZURE_VM_SIZE (Trusted-Launch-capable), COMPUTE_AZURE_IMAGE, optionally
##   COMPUTE_AZURE_TENANT, plus Azure credentials (default credential chain).
.PHONY: integration-test-compute-azure-real
integration-test-compute-azure-real:
	@echo "$(CYAN)$(BOLD)→ Running Azure Trusted Launch live-cloud test (REAL Azure, provisions BILLABLE resources)...$(RESET)"
	COMPUTE_AZURE_LIVE=1 $(GOBIN)/go test -v \
		-tags 'cloud_integration azurecompute $(INTEGRATION_CODEC_TAGS)' \
		-count=1 -timeout 25m ./pkg/compute/azure -run TestAzureCompute_RealCloud
	@echo "$(GREEN)✓ Azure Trusted Launch live-cloud test complete$(RESET)"

## integration-test-compute-cloud-real: Run ALL three real-cloud compute tests (AWS + GCP + Azure)
## Convenience aggregate. Requires every provider's env + credentials (see the per-provider targets)
## and provisions REAL, BILLABLE resources on all three clouds. This is the definitive validation
## that the real cloud APIs + hardware roots of trust work end to end.
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

## integration-test-secureboot-hw: Run the REAL-HARDWARE Secure Boot tier ON the target node (host TPM attestation quote + read-only efivarfs checks). Never run in the devcontainer.
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

# NTP (time synchronization) Tests
#
# NTP_TAGS pins the tag set the time-synchronization surface actually needs:
# the multi-protocol transports plus the QUIC wire codecs. It deliberately
# omits the optional crypto-backend tags (pkcs8/frost/pkcs11/...) so a
# time-sync test run never depends on hardware-backend build variants.
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

# VPN (management-VPN control plane) Tests
#
# These use the fully assembled $(BUILD_TAGS), never a literal list, so every
# QUIC codec the transports need is present.

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


# Integration Tests
# These tests run in docker containers with real services and perform complete end-to-end testing
# Note: Local module directories referenced by go.mod replace directives must be mounted

# Base directory containing all source repositories
# This must match the paths used in go.mod replace directives
SOURCES_BASE := /home/jhahn/sources

# Local module volume mounts for docker - only mount packages with local replace directives in go.mod
# Sibling-module bind mounts, deliberately empty since the tagged-module
# cutover (dependency-resolution.md §2). It used to mount fourteen sibling
# checkouts; none of them exist any more, and go.mod's only local replace is
# `sdk/go => ./sdk/go`. Docker CREATES an empty directory for a missing bind
# source rather than failing, so those mounts were inert and would have
# masked a real mount failure. Kept as an empty variable because 38 recipes
# reference it: emptying the definition fixes every one of them and cannot
# miss a call site the way deleting references could.
DOCKER_MODULE_MOUNTS :=

# The host module cache, mounted into the devcontainer so a suite does not
# re-download ~12G per run. Read-write on purpose: Go writes lock files into
# the cache even when every module is already present, so a read-only mount
# fails. Derived rather than hardcoded so this works off this workstation;
# without go, go's own default (GOMODCACHE, else the first GOPATH entry's
# pkg/mod, else ~/go/pkg/mod).
GO_MODULE_CACHE := $(if $(GO_CMD),$(shell go env GOMODCACHE),$(or $(GOMODCACHE),$(if $(GOPATH),$(firstword $(subst :, ,$(GOPATH)))/pkg/mod),$(HOME)/go/pkg/mod))

# One devcontainer invocation for every per-package integration suite.
#
# CLAUDE.md is explicit that integration tests run in the devcontainer and
# never on the host. Fifteen per-package targets used to call the runner
# script directly, so `make integration-test-bmc` and friends started Open
# vSwitch, swtpm and platformd on whatever workstation invoked make (#492).
# One canned recipe rather than fifteen copies of the docker run, so the
# next target added cannot quietly omit the container.
#
# $(1) is the runner's target keyword, and also names the container so
# concurrent suites do not collide on --name. $(2) is optional extra docker
# arguments (environment for a suite's inputs, more mounts); most suites
# pass nothing.
#
# The source tree is mounted at BOTH paths on purpose: -w is the
# $(SOURCES_BASE) path, while the runner script is invoked by its
# /workspace path. Collapsing them breaks one or the other.
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
## The CI standard's integration stage (handbook ci-standard.md §1). Builds the
## integration-legs stage of build/docker/devcontainer/Dockerfile (the
## integration image with a warm build cache) as $(IT_IMAGE) and
## runs compose.yaml's integration service under the project $(IT_PROJECT):
## its entrypoint is the suite runner, which starts OVS, swtpm and platformd,
## and `all` selects the runner's ALL_TARGETS. The stack is torn down
## (`down --volumes --remove-orphans`) by an EXIT trap, so an error, Ctrl-C or
## SIGTERM tears it down too, and the target exits with the suites' status. CI passes a per-run
## IT_PROJECT and IT_IMAGE so two runs on one daemon never collide.
## Set WITH_CODEC_* or other WITH_* flags for additional build tags.
## CUSTOMIZE (ruling 125): IT_FOREIGN_BASELINE=1 (CI sets it) also writes the
## suites' output to $(IT_LOG) and, when they fail, makes scripts/foreignfailures
## the target's verdict: it passes only when every failure is a row of
## $(FOREIGN_BASELINE), and fails closed on anything it cannot attribute to a
## listed test. Unset, the target exits with the suites' own status, so a
## developer sees every failure (docs/test/integration.md).
## IT_PREBUILT=1 runs the suites in an $(IT_IMAGE) already on the daemon and
## builds nothing: CI's integration legs use the one image the integration-image
## job built for the run (#1119).
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
## integration-test-leg: Run one leg of the integration suite (LEG=<n>)
## CI runs the integration job as one parallel job per leg (#1119). A leg is
## `make integration-test` on that leg's share of the runner's ALL_TARGETS:
## same image, bootstrap and foreign-failure verdict. The legs and what each
## holds: `bash build/docker/devcontainer/run-integration-tests.sh legs`.
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
## integration-test-sdn: Run SDN integration tests in development container
## Starts OVS, swtpm, and platformd via the shared devcontainer runner.
integration-test-sdn: build-devcontainer
	$(call run-integration-suite,sdn)

.PHONY: integration-test-sdn-stress
## integration-test-sdn-stress: Run the SDN stress generators (test/integration/sdn/stress) in development container
## Kept out of integration-test-sdn: they keep every CPU busy for minutes and starved the sdn package's OVS calls.
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

# =============================================================================
# Development Container
# =============================================================================
# build/docker/devcontainer/Dockerfile builds from the repository root in the
# template's stages (handbook devcontainer.md §1): `toolchain`, the image every
# CI stage runs in, and `integration`, the image the integration suites run in.
# scripts/tool-pins.sh holds the base image and tool pins; both make and the
# Dockerfile read it, so the image and the Makefile agree on every version.
include scripts/tool-pins.sh

DEVCONTAINER_DOCKERFILE := build/docker/devcontainer/Dockerfile
DEVCONTAINER_COMPOSE := build/docker/devcontainer/compose.yaml
DEVCONTAINER_IMAGE := trusted-platform-dev:latest
DEVCONTAINER_NAME := trusted-platform-devcontainer

# DEVCONTAINER_WAIT_FOR loads the harness's bounded readiness polls (wait_for,
# no_process_matching) into a `docker exec ... bash -c` script, from the
# checkout the devcontainer mounts at /workspace (#964).
DEVCONTAINER_WAIT_FOR := source /workspace/build/docker/devcontainer/wait-for.sh

# The toolchain image is tagged with a hash of everything baked into it, so a
# change to the Dockerfile, a pin or a module list builds a new tag and an
# unchanged tree reuses the old one. Recursive (=) so the hash runs only when a
# target needs it.
TOOLCHAIN_INPUTS := $(DEVCONTAINER_DOCKERFILE) scripts/tool-pins.sh \
	go.mod go.sum sdk/go/go.mod sdk/go/go.sum \
	$(wildcard build/tools-src/*/go.mod build/tools-src/*/go.sum)
TOOLCHAIN_TAG = $(shell cat $(TOOLCHAIN_INPUTS) | sha256sum | cut -c1-16)
TOOLCHAIN_IMAGE = go-trusted-platform-toolchain:$(TOOLCHAIN_TAG)

# The integration image and the compose project `make integration-test` uses.
# CI passes per-run values.
IT_IMAGE ?= go-trusted-platform-it:local
IT_PROJECT ?= go-trusted-platform-it
# Set to use an $(IT_IMAGE) that is already built (integration-test).
IT_PREBUILT ?=

# The integration container's memory limit, swap included (so no swap): the
# compose integration service (CI's integration legs and soak) and every
# run-integration-suite container. The legs peaked at 4.5 to 12.9 GB with no
# limit on ci-node-2 (#1178); 16g is that plus headroom.
IT_MEMORY ?= 16g

# The cgroup parent of every container CI starts: the run-integration-suite
# container, the compose integration service (exported to it by
# integration-test) and scripts/in-toolchain-image.sh's toolchain container,
# which reads the same variable from its environment. Under ci.slice the runner
# host bounds them together; without a parent they ran in system.slice, outside
# it (#1178). Empty passes no parent: `make ... CI_CGROUP_PARENT=` on a host
# with no ci.slice.
CI_CGROUP_PARENT ?= ci.slice

# The foreign-failure baseline (ruling 125). IT_FOREIGN_BASELINE is empty by
# default: only `make integration-test IT_FOREIGN_BASELINE=1` consults it.
IT_FOREIGN_BASELINE ?=
IT_LOG ?= $(or $(TMPDIR),/tmp)/go-trusted-platform-integration.log
FOREIGN_BASELINE ?= .github/foreign-failures.tsv
# What `make integration-test` hands the suite runner: `all`, or `leg-<n>` when
# integration-test-leg runs it (#1119).
IT_SELECT := all
# The FIPS job's sibling baseline, always consulted by `make test-fips`.
FIPS_LOG ?= $(or $(TMPDIR),/tmp)/go-trusted-platform-fips.log
FIPS_FOREIGN_BASELINE ?= .github/foreign-failures-fips.tsv

# A KEY=value file with the forge credentials the module download needs
# (GOPRIVATE and the GIT_CONFIG_* triple, dependency-resolution.md §6). It
# reaches the build only as the gomodauth BuildKit secret, never as a layer or
# a build argument; .dockerignore keeps the default path out of the context.
MODULE_ENV_FILE ?= .devcontainer/.env

# The docker build arguments every devcontainer stage shares. $(comma) because a
# literal comma inside $(if ...) would end its condition.
# The key of the image's apt layer: the newest Date: of the InRelease files of
# the image's Debian suites (scripts/apt-refresh-key.sh), so a Debian fix
# rebuilds the layer on the next build although BuildKit caches it. The script
# falls back to the UTC date and hour, with a warning, if Debian is unreachable.
# Computed once, and only by a recipe that expands it. Pass APT_REFRESH=<key>
# to rebuild against a fixed key.
APT_REFRESH ?= $(eval APT_REFRESH := $$(shell scripts/apt-refresh-key.sh))$(APT_REFRESH)

DEVCONTAINER_BUILD_ARGS = --build-arg GO_IMAGE=$(GO_IMAGE) \
	--build-arg APT_REFRESH=$(APT_REFRESH) \
	$(if $(GO_BUILD_PROXY),--build-arg GO_BUILD_PROXY=$(GO_BUILD_PROXY)) \
	$(if $(wildcard $(MODULE_ENV_FILE)),--secret id=gomodauth$(comma)src=$(MODULE_ENV_FILE)) \
	-f $(DEVCONTAINER_DOCKERFILE)

# The BuildKit builder the devcontainer images build on. Empty builds on the
# daemon's own builder. CI names this project's docker-container builder, so
# its build cache is this project's alone and can be pruned without touching
# another project's; --load copies the image into the daemon.
BUILDX_BUILDER ?=
# BUILDX_CLIENT_LOAD=1 makes docker-build-it stream the image to this shell's
# `docker load` in place of --load, so it lands in the daemon `docker` here
# talks to, whichever daemon the builder's node runs on. CI's integration legs
# set it for the build a leg makes on a runner without the run's image (#1119).
BUILDX_CLIENT_LOAD ?=
DEVCONTAINER_CLIENT_LOAD = $(and $(BUILDX_BUILDER),$(BUILDX_CLIENT_LOAD))
DEVCONTAINER_BUILD = $(if $(BUILDX_BUILDER),docker buildx build --builder $(BUILDX_BUILDER) $(if $(DEVCONTAINER_CLIENT_LOAD),--output type=docker$(comma)dest=-,--load),DOCKER_BUILDKIT=1 docker build)

.PHONY: docker-build docker-build-integration docker-build-toolchain
## docker-build: Build the integration image and the toolchain image
docker-build: docker-build-integration docker-build-toolchain

## docker-build-integration: Build the integration image as $(IT_IMAGE)
## CI's image job gates $(IT_IMAGE) with `trivy image`: the integration stage,
## without the warm build cache docker-build-it adds.
## Its own target so CI's image job leases $(IT_IMAGE) before the toolchain
## build starts (#1146): until a container names it, another job's reaper may
## remove an image whose cached Created time is past its min-age.
docker-build-integration:
	$(DEVCONTAINER_BUILD) $(DEVCONTAINER_BUILD_ARGS) --target integration -t $(IT_IMAGE) .

## docker-build-toolchain: Build the toolchain image as $(TOOLCHAIN_IMAGE)
docker-build-toolchain:
	$(DEVCONTAINER_BUILD) $(DEVCONTAINER_BUILD_ARGS) --target toolchain -t $(TOOLCHAIN_IMAGE) .

# IT_WARM_CACHE=0 makes docker-build-it skip the warm build cache: it builds
# the integration stage, so a suite run compiles from an empty /gocache.
IT_WARM_CACHE ?= 1
IT_BUILD_TARGET = $(if $(filter 0,$(IT_WARM_CACHE)),integration,integration-legs)

.PHONY: docker-build-it
## docker-build-it: Build the image the integration suites run in as $(IT_IMAGE)
## The integration-legs stage: the integration image with everything a suite
## run compiles already in its build cache, built with the tags
## integration-test passes the runner, so the cache matches (#1119).
## IT_WARM_CACHE=0 builds the integration stage instead, without the warm build
## cache: CI's leg fallback build, which the warm took past its timeout (#1146).
# bash for this recipe alone: BUILDX_CLIENT_LOAD pipes the build into
# `docker load` under pipefail, which dash (Debian's /bin/sh) does not have.
docker-build-it: SHELL := /bin/bash
docker-build-it:
	$(if $(DEVCONTAINER_CLIENT_LOAD),set -o pipefail; )$(DEVCONTAINER_BUILD) $(DEVCONTAINER_BUILD_ARGS) --target $(IT_BUILD_TARGET) \
		--build-arg IT_BUILD_TAGS="$(strip $(TEST_BUILD_TAGS))" -t $(IT_IMAGE) . $(if $(DEVCONTAINER_CLIENT_LOAD),| docker load)

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


# =============================================================================
# SDN Benchmark Tests
# =============================================================================
# Run benchmarks for SDN packages to measure performance of critical paths:
# - VNI/VLAN mapping lookups
# - BGP route insertion/withdrawal and dampening calculations
# - EVPN MAC/IP route encoding/decoding
# - Gateway mode activation and health checks
# - IPAM IP allocation/release throughput
# - DHCP lease management operations
# - OpenFlow message encoding/decoding

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

# =============================================================================
# Enhanced SDN/OVS/QEMU Integration Tests
# =============================================================================

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
## The suite starts its nodes with docker-compose, which the devcontainer has neither the binary nor
## a Docker daemon for, so it carries the topology build tag and stays out of every runner target.
integration-test-sdn-topology:
	go test -v -tags '$(strip $(TEST_BUILD_TAGS)) topology' -count=1 -timeout 30m ./test/integration/sdn/topology/

.PHONY: integration-test-lb
## integration-test-lb: Run the gateway load balancer datapath test in the devcontainer
## Real OVS, kernel conntrack and network namespaces: TCP handshakes through a
## VIP whose replies the load balancer reverse-translates, and through a
## hairpin VIP whose client shares a segment with its backend (#718).
integration-test-lb: build-devcontainer
	$(call run-integration-suite,lb)

.PHONY: integration-test-e2e
## integration-test-e2e: Run end-to-end tests with QEMU VMs and OVS networking
## Without INTEGRATION_TEST_SERVER_ISO/CLIENT_ISO the suite validates its
## infrastructure (OVS bridges, policy engine) and stops before provisioning.
## Set both to paths under the repository (the container sees it at
## /workspace) for the full provisioning run.
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

.PHONY: stress-sdn-ipam
## stress-sdn-ipam: Run IPAM stress tests
stress-sdn-ipam: build-devcontainer
	@echo "Running IPAM stress tests..."
	@docker run --rm --privileged \
		--name go-trusted-platform-ipam-stress \
		-e CGO_ENABLED=0 \
		-v $(PWD):/workspace \
		$(DOCKER_MODULE_MOUNTS) \
		-w /workspace/test/integration/sdn \
		$(DEVCONTAINER_IMAGE) \
		go test -v $(TEST_BUILD_TAGS_ARG) -timeout=15m -run TestIPAM ./stress/...

.PHONY: stress-sdn-bgp
## stress-sdn-bgp: Run BGP stress tests
stress-sdn-bgp: build-devcontainer
	@echo "Running BGP stress tests..."
	@docker run --rm --privileged \
		--name go-trusted-platform-bgp-stress \
		-e CGO_ENABLED=0 \
		-v $(PWD):/workspace \
		$(DOCKER_MODULE_MOUNTS) \
		-w /workspace/test/integration/sdn \
		$(DEVCONTAINER_IMAGE) \
		go test -v $(TEST_BUILD_TAGS_ARG) -timeout=15m -run TestBGP ./stress/...

.PHONY: stress-sdn-dhcp
## stress-sdn-dhcp: Run DHCP stress tests
stress-sdn-dhcp: build-devcontainer
	@echo "Running DHCP stress tests..."
	@docker run --rm --privileged \
		--name go-trusted-platform-dhcp-stress \
		-e CGO_ENABLED=0 \
		-v $(PWD):/workspace \
		$(DOCKER_MODULE_MOUNTS) \
		-w /workspace/test/integration/sdn \
		$(DEVCONTAINER_IMAGE) \
		go test -v $(TEST_BUILD_TAGS_ARG) -timeout=15m -run TestDHCP ./stress/...

.PHONY: stress-sdn-overlay
## stress-sdn-overlay: Run overlay stress tests
stress-sdn-overlay: build-devcontainer
	@echo "Running overlay stress tests..."
	@docker run --rm --privileged \
		--name go-trusted-platform-overlay-stress \
		--device /dev/net/tun:/dev/net/tun \
		--cap-add=NET_ADMIN \
		-e AUTO_START_OVS=true \
		-e CGO_ENABLED=0 \
		-v $(PWD):/workspace \
		$(DOCKER_MODULE_MOUNTS) \
		-w /workspace/test/integration/sdn \
		$(DEVCONTAINER_IMAGE) \
		go test -v $(TEST_BUILD_TAGS_ARG) -timeout=15m -run TestOverlay ./stress/...

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

# =============================================================================
# Docker Compose Based Integration Tests
# =============================================================================

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

.PHONY: integration-test-web
## integration-test-web: Run web frontend E2E tests with swtpm and backend
integration-test-web: devcontainer-compose-up
	@echo "$(CYAN)═══════════════════════════════════════════════════════════════$(RESET)"
	@echo "$(CYAN)  Running Web Frontend E2E Integration Tests$(RESET)"
	@echo "$(CYAN)═══════════════════════════════════════════════════════════════$(RESET)"
	@echo ""
	@echo "$(YELLOW)→ Cleaning up previous test processes...$(RESET)"
	-@docker exec $(DEVCONTAINER_NAME) pkill -9 -f 'platformd-web-test' 2>/dev/null || true
	-@docker exec $(DEVCONTAINER_NAME) pkill -9 -f 'next dev' 2>/dev/null || true
	-@docker exec $(DEVCONTAINER_NAME) pkill -9 -f 'node.*next' 2>/dev/null || true
	@docker exec $(DEVCONTAINER_NAME) bash -c "$(DEVCONTAINER_WAIT_FOR) && \
		wait_for 10 'the previous web test processes to exit' \
			no_process_matching '[p]latformd-web-test|[n]ext dev|[n]ode.*next'"
	@echo "$(YELLOW)→ Initializing swtpm (Software TPM)...$(RESET)"
	-@docker exec $(DEVCONTAINER_NAME) pkill -f 'swtpm socket' 2>/dev/null || true
	@docker exec $(DEVCONTAINER_NAME) rm -rf /tmp/swtpm
	@docker exec $(DEVCONTAINER_NAME) mkdir -p /tmp/swtpm
	@docker exec $(DEVCONTAINER_NAME) swtpm_setup --tpm2 --tpmstate /tmp/swtpm --overwrite --pcr-banks sha256
	@echo "$(YELLOW)→ Starting swtpm daemon...$(RESET)"
	@docker exec -d $(DEVCONTAINER_NAME) swtpm socket --tpm2 \
		--tpmstate dir=/tmp/swtpm \
		--server type=unixio,path=/tmp/swtpm/swtpm.sock \
		--ctrl type=unixio,path=/tmp/swtpm/swtpm.sock.ctrl \
		--flags startup-clear,not-need-init \
		--log level=5,file=/tmp/swtpm/swtpm.log
	@docker exec $(DEVCONTAINER_NAME) bash -c "$(DEVCONTAINER_WAIT_FOR) && \
		wait_for 10 'swtpm socket /tmp/swtpm/swtpm.sock' test -S /tmp/swtpm/swtpm.sock"
	@docker exec $(DEVCONTAINER_NAME) ls -la /tmp/swtpm/
	@docker exec $(DEVCONTAINER_NAME) pgrep -la swtpm || (echo "swtpm failed to start" && exit 1)
	@echo ""
	@echo "$(YELLOW)→ Building backend...$(RESET)"
	@docker exec $(DEVCONTAINER_NAME) bash -c "\
		cd /workspace && \
		go build -tags '$(BUILD_TAGS)' -o bin/platformd-web-test ./cmd/platformd"
	@echo ""
	@echo "$(YELLOW)→ Copying web-test configuration...$(RESET)"
	@docker exec $(DEVCONTAINER_NAME) bash -c "\
		cp /workspace/configs/platform/standalone/web-test.example.yaml /workspace/pkg/config.yaml && \
		rm -rf /workspace/pkg/trusted-data && \
		mkdir -p /workspace/pkg/trusted-data/etc"
	@echo ""
	@echo "$(YELLOW)→ Starting backend with swtpm...$(RESET)"
	@docker exec -d $(DEVCONTAINER_NAME) bash -c "\
		cd /workspace/pkg && \
		../bin/platformd-web-test --config config.yaml --raw-so-pin 123456 --raw-pin 123456 --intermediate 0 --init serve > /tmp/platformd.log 2>&1"
	@echo "$(YELLOW)→ Waiting for the backend web API...$(RESET)"
	@docker exec $(DEVCONTAINER_NAME) bash -c "$(DEVCONTAINER_WAIT_FOR) || exit 1; \
		backend_ready() { curl -sk -X POST -H 'Content-Type: application/json' -d '{\"username\":\"healthcheck\"}' https://localhost:8443/api/v1/webauthn/login/begin 2>&1 | grep -q 'entity not found'; }; \
		if wait_for 60 'platformd web API on https://localhost:8443' backend_ready; then \
			echo 'Backend is ready'; exit 0; \
		fi; \
		echo 'Backend failed to start, showing logs:'; \
		tail -100 /tmp/platformd.log; \
		echo '--- swtpm logs ---'; \
		cat /tmp/swtpm/swtpm.log 2>/dev/null || true; \
		exit 1"
	@echo ""
	@echo "$(YELLOW)→ Installing frontend dependencies...$(RESET)"
	@docker exec $(DEVCONTAINER_NAME) bash -c "\
		cd /workspace/web && \
		npm install --silent"
	@echo ""
	@echo "$(YELLOW)→ Installing Playwright browsers...$(RESET)"
	@docker exec $(DEVCONTAINER_NAME) bash -c "\
		cd /workspace/web && \
		npx playwright install chromium --with-deps"
	@echo ""
	@echo "$(YELLOW)→ Starting Next.js dev server...$(RESET)"
	@docker exec -d $(DEVCONTAINER_NAME) bash -c "\
		cd /workspace/web && \
		npm run dev > /tmp/nextjs.log 2>&1"
	@echo "$(YELLOW)→ Waiting for dev server to start...$(RESET)"
	@docker exec $(DEVCONTAINER_NAME) bash -c "$(DEVCONTAINER_WAIT_FOR) || exit 1; \
		if wait_for 60 'Next.js dev server on http://localhost:3000' curl -s http://localhost:3000; then \
			echo 'Dev server is ready'; exit 0; \
		fi; \
		echo 'Dev server failed to start, showing logs:'; \
		cat /tmp/nextjs.log; \
		exit 1"
	@echo ""
	@echo "$(YELLOW)→ Running Playwright E2E tests...$(RESET)"
	@docker exec $(DEVCONTAINER_NAME) bash -c "\
		cd /workspace/web && \
		npx playwright test --reporter=list" && \
		TEST_RESULT=$$? || TEST_RESULT=$$?; \
	echo ""; \
	echo "$(YELLOW)→ Stopping services...$(RESET)"; \
	docker exec $(DEVCONTAINER_NAME) bash -c "pkill -f 'next dev' || pkill -f 'node.*next' || true"; \
	docker exec $(DEVCONTAINER_NAME) bash -c "pkill -f 'platformd-web-test' || true"; \
	docker exec $(DEVCONTAINER_NAME) bash -c "pkill -f 'swtpm socket' || true"; \
	echo "$(YELLOW)→ Fixing file ownership...$(RESET)"; \
	docker exec $(DEVCONTAINER_NAME) bash -c "chown -R $(shell id -u):$(shell id -g) /workspace/web/.next /workspace/web/test-results /workspace/web/playwright-report 2>/dev/null || true"; \
	if [ $$TEST_RESULT -eq 0 ]; then \
		echo "$(GREEN)✓ Web E2E tests passed!$(RESET)"; \
	else \
		echo "$(RED)✗ Web E2E tests failed$(RESET)"; \
		echo "$(YELLOW)Dev server logs:$(RESET)"; \
		docker exec $(DEVCONTAINER_NAME) cat /tmp/nextjs.log 2>/dev/null || true; \
		echo "$(YELLOW)Backend logs:$(RESET)"; \
		docker exec $(DEVCONTAINER_NAME) tail -50 /tmp/platformd.log 2>/dev/null || true; \
	fi; \
	exit $$TEST_RESULT

.PHONY: dev
## dev: Start development environment (swtpm + backend + frontend) in devcontainer
dev: devcontainer-compose-up
	@docker exec $(DEVCONTAINER_NAME) /usr/local/bin/entrypoint.sh web-dev

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

# =============================================================================
# Development Container with Full Capabilities
# =============================================================================

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


# =============================================================================
# vTPM Integration Tests (using devcontainer)
# =============================================================================
.PHONY: integration-test-vtpm
## integration-test-vtpm: Run full E2E vTPM integration tests (ISO creation + QEMU boot)
## A swtpm that does not start fails this target.
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

# =============================================================================
# Daemon Multi-Protocol Integration Tests
# =============================================================================
.PHONY: integration-test-daemon
## integration-test-daemon: Run daemon multi-protocol integration tests in development container
integration-test-daemon: build-devcontainer
	$(call run-integration-suite,daemon)

.PHONY: integration-test-daemon-local
## integration-test-daemon-local: Run daemon integration tests locally (requires services running)
integration-test-daemon-local:
	@echo "Running daemon integration tests locally..."
	go test -v $(TEST_BUILD_TAGS_ARG) -count=1 -timeout=10m ./test/integration/daemon/...

# =============================================================================
# IAM Multi-Protocol Integration Tests
# =============================================================================
.PHONY: integration-test-iam
## integration-test-iam: Run IAM multi-protocol integration tests in devcontainer
integration-test-iam: build-devcontainer
	$(call run-integration-suite,iam)

.PHONY: integration-test-iam-local
## integration-test-iam-local: Run IAM integration tests locally (requires services running)
integration-test-iam-local:
	@echo "Running IAM integration tests locally..."
	go test -v $(TEST_BUILD_TAGS_ARG) -count=1 -timeout=10m ./test/integration/iam/...


# =============================================================================
# iPXE/PXE Integration Tests
# =============================================================================
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
## integration-test-ipxe-dhcp: Run only DHCP protocol tests
## The runner sets IPXE_DHCP_ENABLED=1 for this target and for ipxe
## (TARGET_ENV); without it the DHCP tests fail, they do not skip.
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

# ==============================================================================
# Code Coverage Targets
# ==============================================================================

# Packages excluded from unit tests and coverage.
#
# NONE of these packages' own _test.go files run in any CI stage (#359, #34).
# Earlier versions of this block said "(tested via integration tests)" beside
# most entries; measured 2026-09-05, that was false twice over: the integration
# runner executes 24 ./test/integration/* directories and ZERO ./pkg/... paths,
# and no workflow invokes `make integration-test` at all. test/integration/
# exercises the subsystems end-to-end; it never compiles these files. Each
# reason below is the prerequisite that keeps the package out, nothing more.
# pkg/arch/testreach_test.go measures this from the workflow files and fails
# when an excluded, test-bearing package is neither run by a stage nor named
# in its deliberatelyUnreached list.
#
# - test/integration: Integration suites; `make integration-test` runs them, no workflow invokes it (#359)
# - sdk/go/gen: Generated protobuf code
# - pkg/api/grpc$$: gRPC server harness — 15 test files / 596 tests that run nowhere (#34); the old
#   "no testable code" reason was false
# - cmd/platformctl$$, cmd/platformd$$: Entry points with main() only
# - examples/: Example code
# - pkg/webservice/v1/test$$: Webservice integration tests
# - pkg/device/dao$$: Only interface definitions, no testable code (tests in subdirs)
# - pkg/platform$$: STALE as of 2026-09-04 (#358) — both halves of the old reason
#   ("TPM/HSM-dependent XKMS code") are false for
#   this package's OWN tests: they use mockTPM throughout, and no CI job invokes
#   `make integration-test`. Re-added to the unit suite through TEST_UNIT_PKGS
#   below; the regex entry stays because that mechanism is deliberately additive.
# - pkg/compute$$: Requires swtpm and OVS
# - pkg/qemu$$: Requires swtpm
# - pkg/swtpm$$, pkg/vtpm$$: STALE as of 2026-10-25 (#964) — their own tests
#   replace swtpm with a stand-in on PATH or serve the in-memory simulator on a
#   unix socket. Re-added to the unit suite through TEST_UNIT_PKGS below.
# - pkg/sdn/netlink$$: Requires root privileges and netlink
# - pkg/ipxe$$: Requires network services
# - pkg/testenv$$: Test helper utilities (not production code)
# - pkg/api/grpc/proto: Generated protobuf code (DO NOT EDIT)
# - pkg/dns/dao$$: DAO types; its one test file (types_test.go) runs nowhere (#34)
# - pkg/initrd$$: Requires TPM, LUKS, block devices, mount
# - pkg/installer$$, pkg/installer/alpine$$: Requires disk partitioning, chroot, apk
# - pkg/firstboot$$: Requires TPM detection, EFI vars, system commands
# - pkg/uefi/firmware$$: Requires efivarfs
# - pkg/uki$$: Requires PE binary tools like objcopy
# - cmd/gatewayd$$, cmd/platform-initrd$$: Entry points with main() only
# - pkg/store/datastore$$: Interfaces and serializer; serializer_test.go runs nowhere (#34)
# - pkg/cli/commands/*: CLI commands require running platformd daemon
#   Includes: iso, kms, iam, vtpm, registry, container, bootstrap, ca, tenant, tpm, sdn,
#   barrier, db, device, fido2, cluster, install, firstboot, profile, acme, authenticode
# - pkg/boot/commands$$, pkg/daemon/commands$$, pkg/sdn/gateway/commands$$: Require running daemon
# - pkg/iso$$: Requires cpio, zstd, grub-mkstandalone, apk tools
# - pkg/storage/luks$$: Requires LUKS/cryptsetup
# - pkg/compute/podman$$: Requires OCI runtime
# - pkg/cli$$: Config loading depends on system state
# - pkg/app$$: Platform initialization requires TPM, KMS, DNS, stores
# - pkg/webservice$$: Webserver startup requires TLS, CA
# - pkg/dns$$: DNSSEC requires XKMS/QuicBaaS key stores
# - pkg/webservice/v1$$: STALE as of 2026-09-02 (#153) — "handler registry setup
#   needs running server" does not hold for this package's own tests, which build
#   a mux and drive it with httptest. Re-added to the unit suite through
#   TEST_UNIT_PKGS below; the regex entry stays because that mechanism is
#   deliberately additive.
# - pkg/webservice/v1/webauthn$$: WebAuthn ceremonies need real authenticator
# - pkg/webservice/v1/rest/platform$$: REST handlers need running gRPC services
# - pkg/platform/system$$: System info gathering depends on host
TEST_EXCLUDE := test/integration|sdk/go/gen|pkg/api/grpc/proto|pkg/api/grpc$$|cmd/platformctl$$|cmd/platformd$$|cmd/gatewayd$$|cmd/platform-initrd$$|examples/|pkg/webservice/v1/test$$|pkg/device/dao$$|pkg/dns/dao$$|pkg/platform$$|pkg/compute$$|pkg/qemu$$|pkg/swtpm$$|pkg/vtpm$$|pkg/sdn/netlink$$|pkg/ipxe$$|pkg/testenv$$|pkg/initrd$$|pkg/installer$$|pkg/installer/alpine$$|pkg/firstboot$$|pkg/uefi/firmware$$|pkg/uki$$|pkg/store/datastore$$|pkg/cli/commands$$|pkg/boot/commands$$|pkg/daemon/commands$$|pkg/sdn/gateway/commands$$|pkg/iso$$|pkg/storage/luks$$|pkg/compute/podman$$|pkg/cli$$|pkg/app$$|pkg/webservice$$|pkg/dns$$|pkg/webservice/v1$$|pkg/webservice/v1/webauthn$$|pkg/webservice/v1/rest/platform$$|pkg/platform/system$$

# TEST_UNIT_PKGS: packages that TEST_EXCLUDE drops from discovery but whose
# _test.go files are self-contained — no platformd, no TPM, no network. They are
# named EXPLICITLY rather than removed from TEST_EXCLUDE so that a future edit to
# that regex cannot silently take them out of the suite again: an excluded
# package's tests run in no CI stage at all and can rot, or stop compiling,
# without turning anything red (#34).
#
# Measured 2026-08-23 at daa039a: pkg/app 37 test files / 2.5s, and
# pkg/daemon/commands 0.03s, both green standalone with the full tag set. The
# TEST_EXCLUDE comment's claim that these "need a running platformd" is stale for
# these two packages; it still holds for the rest of the list.
#
# pkg/cli/commands/bootstrap added 2026-09-02 (#134): 0.48s, green standalone
# with the full tag set, no platformd/TPM/network. It holds the shutdown-watchdog
# tests, which assert that `bootstrap run` returns after cancellation instead of
# requiring SIGKILL (#135). Those tests were written, passed locally, and ran in
# NO CI STAGE — `pkg/cli/commands` is in TEST_EXCLUDE and only ./pkg/app/ and
# ./pkg/daemon/commands/ were re-added. That is exactly the rot this variable's
# comment above warns about, reproduced by the change that added the tests.
#
# pkg/webservice/v1 added 2026-09-02 (#153): measured 22-27s green standalone
# with the full tag set — the router tests build a mux and drive it with
# httptest, so no platformd, no TPM, no network. The TEST_EXCLUDE comment's
# claim that this package "needs a running server" is stale for its own tests,
# exactly as it went stale for pkg/app and pkg/daemon/commands above; that entry
# is now annotated. The package holds the ServiceRegistry tests that pin the 503
# loud-failure contract — the SERVICE_NOT_CONFIGURED discriminator the WebUI
# branches on. Those tests were written against an EXCLUDED package and ran in
# no CI stage, which is #134's lesson repeating: the rot arrives with the change
# that adds the tests, not later.
#
# pkg/dns added 2026-09-02 (#182): 20.8s, green standalone with the full tag
# set, no platformd/TPM/network — the TEST_EXCLUDE comment's claim that it
# needs XKMS/QuicBaaS key stores is stale for the unit tests, which use
# NewMockKeyStore. It holds the resolver's qname-matching tests, which assert
# that a record named "www" does not answer www.anything.example.com. Left
# excluded, those would have run in no CI stage at all.
# pkg/cli/commands/admin added 2026-09-02 (#159): 0.2s green standalone with the
# full tag set, no platformd/TPM/network. The same rot a fourth time, found
# independently the same day as #153's — the admin-claim CLI tests were landing
# in a package no CI stage runs, because `pkg/cli/commands` is in TEST_EXCLUDE.
# Two lanes hitting this on one afternoon is why the pattern is tracked rather
# than the instances. That tracker is #34. (This comment previously named #211,
# which is the sdk/javascript vitest instance and is CLOSED — following it
# produced "closed, so handled" and stopped the reader. Corrected in #358.)
#
# pkg/platform added 2026-09-04 (#358): 1.6s green standalone with the full tag
# set. Its TEST_EXCLUDE reason claimed TPM/HSM dependence; the tests use mockTPM
# throughout — no OpenTPM, no /dev/ open, no TestMain, no network. Unlike the
# five above, this one was verified under the ACTUAL CI condition rather than
# inferred from a dev-host pass: built and run under bwrap with a fresh /dev
# (no /dev/tpm*) and an unshared network namespace, PASS at -count=3, with
# `cat /dev/tpm0` refused inside the same sandbox as the negative control. A
# dev-host pass cannot distinguish "does not need the TPM" from "quietly used
# the one that was there."
#
# test/integration/helpers/surface added 2026-10-12 (#487): the matcher every
# integration suite uses to decide a subtest is "not implemented". It carries no
# build tag and imports only errors and grpc/status, so it runs in-process in
# milliseconds; left to the integration tag it would run in no unit stage.
#
# test/integration/helpers added 2026-10-12 (#502): without the integration tag
# the package is endpoints.go and endpoints_test.go alone, which check that the
# shared endpoint helpers read the variables run-integration-tests.sh exports,
# built from the ports it gives platformd. Every other file keeps the tag.
#
# test/integration/iso added 2026-10-25 (#964 step b): without the integration
# tag the package is runner.go and grub_detector.go with their tests, which
# drive the process-group command runner and the GRUB menu detector over local
# processes, with no platformd. Every other file keeps the tag.
#
# scripts/depscheck added 2026-10-15 (#927): `make deps-check`'s parse and
# decision logic, tested over testdata fixtures with no network. Discovery
# lists only ./pkg/... and ./cmd/..., so without this entry it would run in no
# unit stage.
#
# scripts/foreignfailures added 2026-10-22 (ruling 125): the foreign-failure
# baseline checker the Integration job runs on a failed suite, and the test
# that holds .github/foreign-failures.tsv to the ruling. Same reason as
# depscheck: discovery would not reach it.
#
# test/integration/tenant added 2026-10-25 (#964 step b): without the
# integration tag the package is cli_exec.go, commands.go and cli_exec_test.go,
# the CLI adapter's argument rendering and output parsing, tested with no
# daemon. Every other file keeps the tag.
# pkg/swtpm and pkg/vtpm added 2026-10-25 (#964 step b): green on a host with
# no swtpm and no QEMU. The swtpm tests put a stand-in swtpm on PATH; the vtpm
# tests run the EK certificate injector against the in-memory TPM simulator
# served on a unix socket. The real-swtpm checks stay in test/integration/vtpm.
# test/integration/bmc/vbmc and test/integration/bmc/rmcpsim added 2026-10-25
# (#964 step b): the self-tests of the bmc suite's two simulators, the Redfish
# vBMC and the IPMI RMCP+ responder. Neither package carries a build tag; the
# vbmc tests drive its routes through httptest and the rmcpsim tests talk to
# the responder over 127.0.0.1 UDP, so they need no daemon, container or root.
# TEST_EXCLUDE's test/integration entry kept them out of every unit stage.
# internal/quicbaas added 2026-10-29 (#1204, Codex 8287 P1): the mcp-go v1.4.0
# compatibility tests for the pinned SDK MCP transport. It lies outside the
# ./pkg/... ./cmd/... discovery and TEST_EXCLUDE does not drop it; it runs in
# about 1 s under -race.
TEST_UNIT_PKGS := ./pkg/app/ ./pkg/daemon/commands/ ./pkg/cli/commands/bootstrap/ ./pkg/webservice/v1/ ./pkg/dns/ ./pkg/cli/commands/admin/ ./pkg/platform/ ./pkg/swtpm/ ./pkg/vtpm/ ./test/integration/helpers/surface/ ./test/integration/helpers/ ./test/integration/bmc/vbmc/ ./test/integration/bmc/rmcpsim/ ./test/integration/iso/ ./test/integration/tenant/ ./scripts/depscheck/ ./scripts/foreignfailures/ ./internal/quicbaas/

# RACE_EXCLUDE: packages with data races that are KNOWN and TRACKED. The race
# gate must be green to be a gate, so a package lands here only with an issue
# number, and the entry is deleted when that issue lands — this list only ever
# shrinks. It is empty now: #41 (mockOVSController written from the goroutines
# TestOVSFlowControllerAdapter_ConcurrentAccess starts) was fixed by guarding
# the double with a mutex. The pattern must stay non-empty because grep -E with
# an empty pattern matches every package and test-race would then run none; the
# never-matching ^$$ keeps the filter a no-op.
RACE_EXCLUDE := ^$$

.PHONY: test-race
## test-race: Run unit tests under the race detector (CI gate job)
# Discovery is FAIL-CLOSED: `go list` runs in its own checked assignment — its
# exit status is the assignment's, so `set -e` aborts the recipe — and an empty
# post-filter list is an error. Inside a `$(...)` piped straight into `go test`
# a discovery failure would vanish (no pipefail, stderr suppressed) and the
# gate would pass having raced only TEST_UNIT_PKGS. `-tags` matches the test
# invocation so tag-specific package-loading failures surface here, not there.
RACE_PKGS_DISCOVER = \
	pkgs=$$(go list -tags "$(BUILD_TAGS)" ./pkg/... ./cmd/...); \
	pkgs=$$(printf '%s\n' "$$pkgs" | grep -v -E "$(TEST_EXCLUDE)" | grep -v -E "$(RACE_EXCLUDE)"); \
	[ -n "$$pkgs" ] || { echo "$@: package discovery produced no packages" >&2; exit 1; }

test-race:
	@echo "Running unit tests under the race detector..."
	@set -e; \
	$(RACE_PKGS_DISCOVER); \
	go test -race -tags "$(BUILD_TAGS)" -skip "$(TEST_SKIP)" -timeout 20m $$pkgs $(TEST_UNIT_PKGS)

## print-race-pkgs: Print test-race's package set on one line (batch.yml race-full and bench read it)
#
# The same fail-closed discovery as test-race, so batch.yml's race-full job
# races exactly the packages the CI Race job does, at a different -count.
.PHONY: print-race-pkgs
print-race-pkgs:
	@set -e; \
	$(RACE_PKGS_DISCOVER); \
	echo $$pkgs $(TEST_UNIT_PKGS)

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
# Both steps keep going on failure ON PURPOSE — the merge below needs both
# profiles, and a partial coverage number is still worth producing. What is NOT
# on purpose is doing it silently: the `|| true` here used to hide a failing
# suite completely, so a red run produced a coverage report that read as clean.
# Failures are now recorded and reported at the end (#243).
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

# ==============================================================================
# Code Quality Targets
# ==============================================================================

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
## check-go-build-tags: Fail if a target ci-template calls drops GO_BUILD_TAGS (#960)
#
# Dry-runs (`make -n`) each target with a probe tag and fails unless the
# probe reaches a command line other than an `echo`: a go build/test/vet,
# golangci-lint, gosec, govulncheck or the integration runner. Nothing
# builds and nothing runs. `test` is itself probed and depends on this
# target, so the probe run sets GO_BUILD_TAGS_PROBING to stop the recursion
# (`make -n` still executes recipe lines that name $(MAKE)).
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

# ==============================================================================
# Security Scanning Targets
# ==============================================================================

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

# Modules scanned by `make vuln`, kept in step with the module split: the root
# module and the separately-versioned SDK. Both are blocking.
GOVULN_MODULES := . sdk/go

# govulncheck is blocking (devops.md §8) and is also the §9 forcing function for
# toolchain currency. One finding has NO fixed version published upstream and is
# allowlisted here by ID; every other finding — including a new one in these
# same modules — fails the target. Re-check on each dependency bump and delete
# an entry the day its fix ships.
#   GO-2026-4736 (allowlisted 2026-08-14; re-verified 2026-08-20 and again
#       2026-09-08 on gobgp/v4 v4.9.0 — issue #25)
#       github.com/osrg/gobgp/v4: a remotely-triggerable panic on a malformed
#       NEXT_HOP path attribute crashes the BGP speaker. Reached from
#       pkg/sdn/bgp/speaker.go (gobgpServerWrapper.Start -> BgpServer.Serve).
#
#       The 2026-09-08 migration to gobgp/v4 v4.9.0 (#556) did NOT close it:
#       govulncheck v1.8.0 still reports "Fixed in: N/A" for v4.9.0. A claim
#       circulating that v4.3.0 fixed it is false against the database; the
#       database is the authority here. The speaker's exposure is unchanged:
#       it peers only with neighbours named in configuration (the iBGP relays),
#       under RFC 8212 default-deny policy and a per-family prefix limit.
#       Phase 2.0 of #553 (privilege-separated processes) bounds a speaker
#       crash to the bgp process.
#
#       Exposure: the speaker only peers with neighbours named in configuration,
#       inside the fabric, and the BGP edge is not in production use.
#
#       CLOSING CONDITION (issue #25): the day upstream publishes a fixed
#       release, bump gobgp, DELETE this entry and the ID from GOVULN_ALLOW
#       below, and mark the tracking issue done. Watch
#       https://pkg.go.dev/vuln/GO-2026-4736.
GOVULN_ALLOW := GO-2026-4736

# Each module is scanned in two steps (#940). The symbol scan builds SSA and a
# call graph for the whole import closure; on module . it outgrew the CI job's
# 12 GiB memory limit and was OOM-killed, and neither GOMEMLIMIT nor scanning
# the packages in groups bounds it (cmd/platformctl alone keeps a >5 GB live
# heap). So every package is first scanned for vulnerable IMPORTS
# (-scan package, no SSA, well under 1 GiB). A called vulnerability is always
# an imported one, so when every imported ID is allowlisted the symbol scan's
# verdict is already known and it is not run. Only an imported ID outside the
# allowlist runs the symbol scan, which decides as before whether the code calls
# it; if that scan cannot complete, the target fails.
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

# Directories excluded from the filesystem scan. CI runs this same target
# through `make security` in the toolchain image (devops.md §4). test/ and vbmc/ are harnesses and examples/ is a sample tree —
# none ship in a release. web/node_modules is a build artifact; web/ itself is
# NOT skipped, because the Next.js frontend is shipped and its lockfiles are in
# scope. Suppressions belong in .trivyignore with a reason and a date, not here.
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
## security: Run the full security-analysis suite (devops.md §8)
# The contract CI calls: gosec, govulncheck, go mod verify and trivy fs, in the
# same form a developer runs locally. Container images are covered separately by
# `make trivy-image`, which needs a built image. trivy fails closed when the CLI
# is not on PATH: a suite that silently skips a scanner is not a passing suite.
security: gosec vuln mod-verify trivy
	@echo "$(GREEN)$(BOLD)✓ Security suite passed!$(RESET)"

.PHONY: check
## check: Run all code quality and security checks
check: fmt-check vet lint gosec vuln
	@echo "$(GREEN)$(BOLD)✓ All quality checks passed!$(RESET)"

# ==============================================================================
# Tool Installation Targets
# ==============================================================================

.PHONY: install-tools
## install-tools: Install all development and security tools
install-tools: install-gosec install-govulncheck install-trivy install-grype install-golangci-lint install-gocovmerge
	@echo "$(GREEN)$(BOLD)✓ All development tools installed$(RESET)"

.PHONY: install-gosec
## install-gosec: Install gosec security scanner
install-gosec: $(GOSEC)
	@echo "$(GREEN)  ✓ gosec $(GOSEC_VERSION) at $(GOSEC)$(RESET)"

# Built from the gosec tools module ($(GOSEC_SRC)) with this module's toolchain
# into a version-stamped directory; make skips it when the binary is present.
# Never resolved from PATH.
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
# Make skips this entirely when the binary is already there, so `make lint` does
# not pay an install on every invocation.
#
# The previous version of install-golangci-lint could not fix the problem it was
# offered for: it downloaded a PREBUILT v2.11.2 — a third version, by exactly the
# mechanism that causes the toolchain mismatch — and short-circuited on
# `command -v golangci-lint`, so with a broken binary already on PATH it printed
# "already installed" and did nothing.
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

# ==============================================================================
# CI Pipeline Targets
# ==============================================================================

.PHONY: ci-local
## ci-local: Run CI pipeline locally (requires all tools installed)
# `security` is the full §8 suite (gosec, govulncheck, go mod verify, trivy fs)
# and replaces the loose `gosec vuln trivy` chain: devops.md §4 requires
# `make ci` to include it.
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
## race: Run tests with race detector
# The exit status is the RESULT, so it has to survive both the pipe and the
# recipe. `$$?` after a pipeline is tee's status, not go test's, and /bin/sh
# here is dash, which has no `pipefail` — so the status is stashed inside the
# braces and read back. Before this the recipe ended `|| true` with an
# unconditional `✓`, and a detected race, a compile error or a timeout kill all
# reported success (#243).
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

# ==============================================================================
# Releases
# ==============================================================================

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


# Docker
# Both bake groups (docker-bake.hcl) run on the default buildx builder; the
# arm64 group is built through binfmt/qemu-user-static (registered by `init`),
# not on a remote arm64 docker context.
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

# Docker :: PXE Boot Container (bootstrap)
# Builds the PXE boot container: the static pxeboot binary, Samba and
# supervisord. It carries no installer media — every media set it serves
# comes from a netboot media build (make netboot-media) the deployer stages
# under /data/media.
#
# Usage: make pxeboot-container
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

# U-Boot for the Raspberry Pi factory image (build/docker/uboot-builder):
# rpi_arm64 (SPI TPM, loaded by the Pi firmware as kernel8.img) and qemu_arm64
# (the emulated stand-in), both with EFI TCG2 measured boot and EFI Secure
# Boot whose PK/KEK/db are preseeded from UBOOT_KEYS_DIR. One build per key
# set; the output carries the cache key of its inputs.
UBOOT_KEYS_DIR   ?= $(HOME)/.trusted-platform/secure-boot
UBOOT_OUTPUT_DIR ?= build/docker/uboot-builder/output

.PHONY: uboot-build
## uboot-build: Build the rpi_arm64 and qemu_arm64 U-Boot binaries with the Secure Boot keys from UBOOT_KEYS_DIR preseeded
uboot-build:
	$(MAKE) -C build/docker/uboot-builder build KEYS_DIR=$(abspath $(UBOOT_KEYS_DIR)) OUTPUT_DIR=$(abspath $(UBOOT_OUTPUT_DIR))

# iPXE: the arm64 EFI iPXE the PXE server hands to a Raspberry Pi or the
# QEMU virt stand-in after U-Boot. Upstream's binary halts under U-Boot's
# polled EFI (build/docker/ipxe-builder/README.md says why); this one is
# built with NAP_NULL and cached by its inputs' digests.
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

# The virt kernel: the QEMU virt stand-in's kernel, cross-built from Alpine's
# linux-lts version with the memory-mapped TIS TPM driver Alpine's aarch64
# kernels lack (build/docker/virt-kernel-builder/Dockerfile says why).
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

# The platform-required kernel options (build/docker/kernel-config) checked
# against the Alpine kernels the platform ships but does not build: linux-lts
# on x86_64 and aarch64, linux-rpi on aarch64. Built in or module both count;
# the arm64 run needs binfmt (as the assemble container does). Fails, after
# checking every package, if any of them misses an option. The amd64 run is
# last so the local alpine:<release> tag, which a --platform run re-points,
# is left on amd64 for the builders that use it untagged.
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

# strongSwan for the overlay's IPsec transport (build/docker/strongswan-builder,
# docs/sdn/engineering.md "IPsec transport"): charon + swanctl from a pinned
# release whose tarball must carry the pinned release key's signature and the
# pinned SHA-256, built for Alpine 3.22 (musl) on amd64 and arm64 (arm64 under
# binfmt/qemu-user) and packaged as signed apks with an OpenRC service. The same
# build packages the PKCS#11 module host (trusted-platform-p11-host: the glibc
# p11-kit server that hosts the go-xkms module for musl charon, ipsec-module-host
# below) with its OpenRC service. The output is what the install media carry
# (--platform-apk-dir). Sign with APK_SIGNING_KEY=<path>/<name>.rsa
# (<name>.rsa.pub beside it); without it the build uses a per-build ephemeral
# key (dev only).
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

# The ipsec integration suite (test/integration/ipsec) runs two musl charon
# peers, each in its own network namespace, authenticating IKEv2 through the
# go-xkms PKCS#11 module, and asserts the ESP SAs with `ip xfrm`. It runs on
# both architectures: natively in the devcontainer on amd64, and inside an
# aarch64 VM (qemu-system-aarch64, TCG) on arm64, because qemu-user refuses
# NETLINK_XFRM and charon will not start without it. Its inputs are built
# here, on the host, per architecture:
#   - rootfs-<arch>.tar: Alpine with the strongSwan and module-host apks
#     installed through apk (signatures checked), as a node has them;
#   - modulehost-<arch>.tar: a glibc root filesystem (Ubuntu 26.04, p11-kit
#     0.26.2 like Alpine's client) whose p11-kit server hosts the module,
#     built c-shared against glibc: a Go c-shared library cannot be loaded by
#     a musl process (golang/go#13492), so charon loads p11-kit-client.so
#     (docs/sdn/engineering.md §9.2). strongswan-build packages it as the
#     trusted-platform-p11-host apk, so it reaches the peers through the rootfs;
#   - for arm64, the VM's kernel and initramfs and the suite's own test
#     binary cross-compiled for arm64.
# IPSEC_XKMS_VERSION pins the go-xkms the module is built from: the first
# whose module survives C_Finalize + C_Initialize (which p11-kit's server
# performs on every connection) and signs raw CKM_ECDSA (which strongSwan
# uses), both from go-xkms#1387, released in v0.48.0-alpha. The go-xkms the
# platform's go.mod resolves (v0.17.0-alpha) predates both fixes.
IPSEC_WORK_DIR     := work/ipsec
IPSEC_ARCHES       := amd64 arm64
IPSEC_PEER_IMAGE   := trusted-platform-ipsec-peer
IPSEC_HOST_IMAGE   := trusted-platform-ipsec-modulehost
IPSEC_XKMS_VERSION ?= v0.48.0-alpha
# --init: the peers' OpenRC services run supervise-daemon, whose `--stop`
# waits for the supervisor's PID to disappear. The supervisor is reparented
# to the container's PID 1 when it exits, and `go test` as PID 1 never reaps
# it, so without an init the zombie keeps `rc-service charon stop` waiting
# forever (measured: [supervise-daemo] <defunct> under PID 1).
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


# Docker run targets. docker-run itself runs a command in the toolchain image
# (Development Container section); this is the interactive builder shell.
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


# ISO
# Build ISOs via the in-CLI builder. The previous Docker-based
# iso-hwtpm / iso-swtpm targets and the trusted-platform-iso-builder
# image were removed; `bin/platformctl iso create` is the supported
# and intended workflow now (downloads Alpine, customizes, generates
# Secure Boot keys, and emits the bootable ISO).
# Factory disk images (pkg/diskimage, `platformctl diskimage`): the installer
# runs inside the arm64 assemble container against a loop-mounted image.
# Requires the arm64 binaries (rpi-binaries); `platformctl diskimage create`
# itself generates the Secure Boot keys in UBOOT_KEYS_DIR when they do not
# exist, builds (or reuses) U-Boot in UBOOT_OUTPUT_DIR for that key set, and
# builds the assemble container image. uboot-build and
# docker-diskimage-builder-load remain for doing those steps on their own.
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

# The qemu-virt image and the U-Boot it boots with, as the integration suite
# sees them. Both are produced on the host (binfmt + privileged assemble
# container) and handed to the devcontainer read-only.
DISKIMAGE_QEMU_IMG   := bin/trusted-platform-qemu-virt.img
DISKIMAGE_UBOOT_QEMU := $(UBOOT_OUTPUT_DIR)/qemu_arm64/u-boot.bin
DISKIMAGE_UBOOT_RPI  := $(UBOOT_OUTPUT_DIR)/rpi_arm64/u-boot.bin

# The suite's inputs as the devcontainer sees them. The work directory is
# under the mounted source tree (work/ is ignored by git), not the
# container's tmpfs /tmp: the boot copies the image there and the guest
# writes to it.
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

# The aarch64 network-boot suite: QEMU virt booted from the qemu_arm64
# U-Boot on the PXE test bridge — the Raspberry Pi stand-in from U-Boot
# onward. Boots Alpine's own aarch64 netboot kernel and initramfs, pinned
# to the release branch pkg/iso builds from, fetched once into bin/.
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

# The NAT64 suite (#601) runs in a VM that carries its own kernel. Jool is
# a kernel module and a container shares the host's kernel, so the suite
# boots Alpine linux-lts with the jool-modules-lts built for exactly that
# kernel (the fleet's pairing) under QEMU/KVM inside the devcontainer. The
# guest suite is test/integration/sdn built with the nat64vm tag.
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

# The arm64 userspace suite runs the aarch64 platformd on musl against a
# swtpm inside an arm64 Alpine container (binfmt on the host, like the
# assemble container), without booting anything: minutes, not an hour.
DISKIMAGE_USERSPACE_IMG := trusted-platform-alpine-swtpm:arm64
DISKIMAGE_USERSPACE_BIN := bin/aarch64/diskimage-userspace.test

# The software TPM the userspace suite talks to runs on the HOST, natively,
# with its state directory bind-mounted into the arm64 container: under
# qemu-user emulation swtpm never creates its Unix sockets (bind() fails or
# the socket silently does not appear, measured 2026-09-20 with swtpm's own
# privilege drop, with docker exec --user tss and with a shell wrapper),
# while a connect() from the emulated platformd to a host-made socket works.
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


# Browser targets — launch with trusted CA from QEMU server
# Usage:
#   make chrome       # Chrome trusting server CA
#   make firefox      # Firefox trusting server CA
#   make browser      # Auto-detect (prefers Chrome for WebAuthn)
#
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
## Without ISOs it boots its framework VM on an isolated bridge. Set
## INTEGRATION_TEST_SERVER_ISO and INTEGRATION_TEST_CLIENT_ISO to paths under
## the repository (the container sees it at /workspace) for the full ISO run.
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

# Build all binaries for ISO/deployment (three-binary architecture)
# All binaries are static by default
# - platformd: Daemon only (serves as the system service)
# - platformctl: Full CLI with all user commands
# - platform-initrd: Minimal binary for initramfs boot operations
.PHONY: binaries
binaries: build platform-initrd
	@echo "Built all static binaries:"
	@echo "  platformd:       $$(du -h $(PLATFORMD) | cut -f1) (daemon)"
	@echo "  platformctl:     $$(du -h $(PLATFORMCTL) | cut -f1) (CLI)"
	@echo "  platform-initrd: $$(du -h $(PLATFORM_INITRD) | cut -f1) (initramfs)"

.PHONY: binaries-static
binaries-static: binaries
	@echo "binaries-static target is deprecated. Use 'make binaries' instead (now produces static binaries by default)."

# Every binary a linux/arm64 node (an RPi, for one) needs, cross-
# compiled as pure Go into $(ARM64_BIN_DIR).
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



# Builds never resolve through a workspace: modules come from Gitea tags
# (dependency-resolution.md §2). Immunizes against stray go.work files.
export GOWORK=off

# ---- dependency-resolution.md targets (2026-08-13 cutover) ----
# deps-latest runs before compiling in a consumer repo. It picks the highest
# tag INCLUDING -alpha prereleases — bare 'go get @latest' ignores
# prereleases and would downgrade to legacy v0.0.0.

.PHONY: deps-latest

deps-latest:
	@GOWORK=off sh -c ' \
	SELF=$$(go list -m); \
	for m in $$(go list -m -f "{{if not .Indirect}}{{.Path}}{{end}}" all 2>/dev/null | grep "^github.com/jeremyhahn/" | grep -vx "$$SELF"); do \
	  case "$$(go list -m -f "{{if .Replace}}{{.Replace.Path}}{{end}}" "$$m" 2>/dev/null)" in .*|/*) continue;; esac; \
	  V=$$(go list -m -versions "$$m" 2>/dev/null | tr " " "\n" | tail -1); \
	  if [ -n "$$V" ] && [ "$$V" != "$$m" ]; then go get "$$m@$$V" || exit 1; fi; \
	done; go mod tidy'

# deps-check is the CI standard's latest-version stage (handbook ci-standard.md
# §1, devops.md §4). scripts/depscheck fails when a direct require or a version
# replace in go.mod or sdk/go/go.mod is behind its latest version and its line
# carries no comment naming the reason (devops.md §9). First-party modules are
# compared with their highest tag including -alpha, the version deps-latest
# moves to (dependency-resolution.md §3). It needs the module proxy and the dev
# Gitea: under GOPROXY=off it fails with that reason instead of passing.
.PHONY: deps-check
## deps-check: Fail when a dependency is behind its latest version without a go.mod reason comment
deps-check:
	@$(GO) run ./scripts/depscheck -go $(GO) . sdk/go

# ---- release-alpha: handbook template release-alpha v2.4.0 ----
# make release-alpha VERSION=vX.Y.Z-alpha cuts an internal alpha from main
# (release-versioning.md §1a). It writes VERSION, re-pins the root's sdk/go
# requirement, commits, tags vX.Y.Z-alpha and sdk/go/vX.Y.Z-alpha (annotated,
# signed through agent-git.sh), and pushes the commit and exactly those two
# tags in one atomic push. CHANGELOG.md must already hold a
# "## [X.Y.Z-alpha]" section. build/make/ holds verbatim copies of the
# handbook templates: refresh them by copying, never edit them here.
# Set these before the include; the template reads them as it is parsed.
REPO_NAME        ?= go-trusted-platform
AGENT_GIT        ?= agent-git.sh
RELEASE_REMOTE   ?= origin
LOCKSTEP_MODULES := sdk/go
include build/make/release-alpha.mk

# The template's version guard is an ordinary recipe line, which `make -n`
# prints instead of running. This prerequisite runs the same guard under
# -n as well ('+'), so a dry run without VERSION fails like the real one.
.PHONY: release-alpha-version
release-alpha: release-alpha-version
release-alpha-version:
	+@test -n "$$REL_VERSION" || { echo 'ERROR: state the version explicitly: make release-alpha VERSION=vX.Y.Z-alpha (release-versioning.md decides patch/minor/major — the recipe refuses to guess)'; exit 1; }
