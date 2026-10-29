# go-trusted-platform devcontainer: one Dockerfile, the shipped stages built
# FROM base (handbook devcontainer.md §1).
#
#   tools        build-only: govulncheck and trivy, built or downloaded into /out;
#                swag (integration only) into /out-integration
#   modules      build-only: the module caches of the root module, sdk/go and
#                the build/tools-src tool modules, fetched with the forge
#                credentials
#   base         the Go toolchain, the C toolchain cgo and -race need, the
#                OpenSSL headers the TPM simulator compiles against, a non-root
#                user and the verified module cache; GOPROXY=off
#   toolchain    base + every tool the Makefile calls. `make build`, `make test`,
#                `make security` and `make deps-check` run here, in CI too.
#   integration  base + the integration suite's system packages (swtpm,
#                tpm2-tss, Open vSwitch, qemu, cryptsetup, the ISO and
#                initramfs tools, Node and the Playwright libraries) and the
#                source at /workspace. `make integration-test` runs it under the
#                privileged compose service (compose.yaml beside this file).
#
# Build with `make docker-build` (both images) or `make build-devcontainer`
# (the integration image as trusted-platform-dev:latest): they pass GO_IMAGE
# from scripts/tool-pins.sh, the one pin file the Makefile also reads, and the
# forge credentials as the gomodauth BuildKit secret. GO_IMAGE has no default
# here, so a build that bypasses the pin file fails instead of drifting.
# Requires BuildKit.
#
# The build context is the repository root, filtered by the root .dockerignore.
# A CI runner reaches its Docker daemon through a socket, so a bind mount would
# resolve on the daemon's host, where the checkout does not exist: integration
# bakes the source in, and CI copies the checkout into a toolchain container
# (scripts/in-toolchain-image.sh) instead of mounting it.
#
# Debian, not Alpine (devops.md §9a): the integration suite needs Debian's
# swtpm, tpm2-tss, Open vSwitch and qemu packages, and the cgo TPM simulator
# links glibc.

ARG GO_IMAGE
# Build-time module and tool downloads go through this proxy (devcontainer.md
# §4). The caller's environment supplies another; no tracked file does.
ARG GO_BUILD_PROXY=https://proxy.golang.org,direct

# ---------------------------------------------------------------------------
FROM ${GO_IMAGE} AS tools
ARG GO_BUILD_PROXY
ARG TARGETARCH
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOPROXY=${GO_BUILD_PROXY} GOBIN=/out
COPY scripts/tool-pins.sh /tmp/tool-pins.sh
# swag builds from its build/tools-src module: `go install swag@version` would
# link the stale dependencies swag's own go.mod requires, which the image's
# trivy gate reports (#933). golangci-lint, actionlint and gosec are not here:
# the Makefile builds each from its build/tools-src module, whose cache the
# modules stage downloads.
COPY build/tools-src/swag/ /tmp/tools-src/swag/
RUN set -eu; \
    . /tmp/tool-pins.sh; \
    go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"; \
    go build -C /tmp/tools-src/swag -mod=readonly -trimpath \
      -o /out-integration/swag github.com/swaggo/swag/cmd/swag; \
    case "${TARGETARCH:-amd64}" in \
      amd64) arch=64bit; sum="${TRIVY_SHA256_LINUX_AMD64}" ;; \
      arm64) arch=ARM64; sum="${TRIVY_SHA256_LINUX_ARM64}" ;; \
      *) echo "no trivy pin for ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    v="${TRIVY_VERSION#v}"; \
    f="trivy_${v}_Linux-${arch}.tar.gz"; \
    curl -fsSL -o "/tmp/${f}" "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/${f}"; \
    echo "${sum}  /tmp/${f}" > /tmp/trivy.sha256; \
    sha256sum -c /tmp/trivy.sha256; \
    tar -xzf "/tmp/${f}" -C /out trivy; \
    rm -f "/tmp/${f}"

# ---------------------------------------------------------------------------
# github.com/jeremyhahn/* modules resolve from the forge through git, which the
# golang bookworm image carries.
FROM ${GO_IMAGE} AS modules
ARG GO_BUILD_PROXY
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOMODCACHE=/gomodcache GOPROXY=${GO_BUILD_PROXY}
WORKDIR /src

# Download the module caches in their own layer. Credentials for the project
# forge arrive as the optional gomodauth BuildKit secret (the K=V lines of
# .devcontainer/.env), mounted for this RUN only: sourced, never written to a
# layer or a command line. With no secret, modules resolve from the public
# proxy, so a module only the forge serves fails the build here, loudly.
# sdk/go is copied because the root go.mod replaces it with ./sdk/go.
# The cache is opened for reading by any uid (the toolchain image runs as the
# invoking user) in this same RUN, while its files are still in the layer
# being written. A chmod -R in a later layer copies every file of the cache up
# into a new layer: 107 s on ci-node-2 and 1468 to 2287 s on omega
# (go-trusted-platform run 70307, CA m1594). COPY --from keeps the modes.
COPY go.mod go.sum ./
COPY sdk/go/go.mod sdk/go/go.sum ./sdk/go/
COPY build/tools-src/ ./build/tools-src/
RUN --mount=type=secret,id=gomodauth \
    set -eu; \
    if [ -s /run/secrets/gomodauth ]; then \
      set -a; . /run/secrets/gomodauth; set +a; \
      echo "==> go mod download: Gitea module credentials mounted"; \
    else \
      echo "==> go mod download: no module credentials mounted; github.com/jeremyhahn/* resolves from the public proxy only"; \
    fi; \
    go mod download; \
    (cd sdk/go && go mod download); \
    for d in build/tools-src/*/; do (cd "$d" && go mod download); done; \
    chmod -R a+rX /gomodcache
RUN set -eu; \
    go mod verify; \
    (cd sdk/go && go mod verify)

# ---------------------------------------------------------------------------
FROM ${GO_IMAGE} AS base
ARG DEBIAN_FRONTEND=noninteractive
# GOTOOLCHAIN=local: a go.mod asking for a newer Go fails instead of
# downloading one. CGO for -race and the TPM simulator.
ENV GOTOOLCHAIN=local \
    CGO_ENABLED=1 \
    GOFLAGS=-mod=readonly \
    GOMODCACHE=/gomodcache \
    GOCACHE=/gocache
# cpio: pkg/diskimage/netboot repacks its installer initramfs with it.
# libssl-dev: go-tpm-tools' simulator compiles the reference TPM against
# OpenSSL (#149).
# APT_REFRESH keys the apt layer, which BuildKit would otherwise cache forever.
# `make docker-build` (CI's image job) passes the newest Date: of the InRelease
# files of bookworm, bookworm-updates and bookworm-security
# (scripts/apt-refresh-key.sh), so the layer is rebuilt whenever Debian
# publishes and `apt-get upgrade` takes Debian's fixes before `trivy image`
# scans for them (libexpat CVE-2025-59375 / CVE-2026-77214, PR #991). The dated
# default applies only to a build that passes nothing. A new key rebuilds this
# layer and, through FROM base, every apt layer of toolchain and integration.
ARG APT_REFRESH=2026-10-22
RUN set -eu; \
    echo "apt refresh: ${APT_REFRESH}"; \
    apt-get update; \
    apt-get upgrade -y; \
    apt-get install -y --no-install-recommends \
      build-essential pkg-config libssl-dev openssl ca-certificates \
      git make cpio xz-utils zstd file; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd -g 10001 dev; \
    useradd -m -u 10001 -g dev -d /home/dev dev; \
    install -d -m 0755 -o 10001 -g 10001 /src
COPY --from=modules /gomodcache /gomodcache
# Open the (empty) build cache for writing to any uid; the module cache was
# opened for reading in the modules stage. The race-instrumented standard
# library is not pre-built here: it cost 11 minutes of every uncached image
# build (CA m639), and the race job builds it on first use.
RUN install -d -m 0777 /gocache
# Nothing fetches a module at run time (devcontainer.md §4).
ENV GOPROXY=off

# ---------------------------------------------------------------------------
FROM base AS toolchain
ARG DEBIAN_FRONTEND=noninteractive
# GOTMPDIR: the go command's work directory ($WORK: every compiled package and
# linked test binary of a run) goes beside the build cache, on disk, wherever
# that cache is mounted. Under the default it lands in the size-capped /tmp
# tmpfs, which `make test` over the whole tree overflows (#933). testing's
# t.TempDir() follows GOTMPDIR, so test directories land on /gocache, which any
# uid can write and is not sticky: a test that needs a private ancestor chain
# makes its directory under os.TempDir() instead (cmd/deployer-pin
# privateTempDir).
# TMPDIR: the linker does not follow GOTMPDIR. An external (cgo) link writes
# its objects under os.MkdirTemp("", "go-link-") (cmd/link hostlinksetup), and
# `make test` links one test binary per CPU at once, so in /tmp those overflow
# it too (#933). /var/tmp is on disk and, like /tmp, sticky under root-owned
# ancestors, so os.TempDir() still passes deployer-pin's ancestor check, and
# it is short enough for the Unix socket paths tests bind under it.
# TRIVY_CACHE_DIR: trivy's vulnerability DB (1.6 GB unpacked) and its scan cache
# go beside the build cache too, for every trivy run in this image (`make
# trivy`, CI's `trivy image`). Under the default, $HOME/.cache/trivy, the DB
# lands in /tmp beside the module cache CI's security step downloads, and the
# two overflow it (#933).
ENV HOME=/tmp \
    GOTMPDIR=/gocache \
    TMPDIR=/var/tmp \
    TRIVY_CACHE_DIR=/gocache/trivy
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends bash curl jq shellcheck; \
    rm -rf /var/lib/apt/lists/*; \
    git config --system --add safe.directory '*'
COPY --from=tools /out/ /usr/local/bin/
WORKDIR /src
USER dev:dev

# ---------------------------------------------------------------------------
# The suite runs as root, privileged: it starts Open vSwitch, swtpm and qemu,
# and attaches loopback LUKS2 volumes (docs/test/integration.md). It is the
# devcontainer for interactive work too (`make devcontainer-shell`).
FROM base AS integration
ARG DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
SHELL ["/bin/bash", "-c"]

# Networking and process tools the suites and the entrypoint call. Every
# package in this stage is one a suite, the runner or a Makefile target run
# here calls: each one more is attack surface the trivy image gate scans (#933).
RUN apt-get update && apt-get install -y \
    curl jq \
    iproute2 iputils-ping dnsutils netcat-openbsd \
    procps psmisc \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# chrony for the ntp suite: platformd renders chrony.conf from the
# integration config's ntp: section and drives chronyc against the chronyd
# the runner starts on it (run-integration-tests.sh start_chronyd).
RUN apt-get update && apt-get install -y chrony \
    && rm -rf /var/lib/apt/lists/*

# TPM 2.0 software stack and swtpm (software TPM).
RUN apt-get update && apt-get install -y \
    tpm2-tools \
    libtss2-dev \
    libtss2-esys-3.0.2-0 \
    libtss2-fapi1 \
    libtss2-mu0 \
    libtss2-rc0 \
    libtss2-sys1 \
    libtss2-tcti-device0 \
    libtss2-tcti-mssim0 \
    libtss2-tcti-swtpm0 \
    libtss2-tcti-tabrmd0 \
    libtss2-tctildr0 \
    swtpm \
    swtpm-tools \
    libtpms0 \
    libtpm2-pkcs11-1 \
    && rm -rf /var/lib/apt/lists/*

# PKCS#11, HSM and smart card tooling; FIDO2 tooling.
RUN apt-get update && apt-get install -y \
    opensc \
    opensc-pkcs11 \
    libsofthsm2 \
    softhsm2 \
    pcscd \
    libpcsclite-dev \
    libu2f-udev \
    libfido2-dev \
    fido2-tools \
    && rm -rf /var/lib/apt/lists/*

# QEMU and OVMF for the VM-based suites. busybox-static populates the minimal
# initramfs the Secure Boot FIPS-kernel insmod-rejection test uses
# (test/integration/secureboot).
RUN apt-get update && apt-get install -y \
    qemu-system-x86 \
    qemu-utils \
    qemu-efi-aarch64 \
    qemu-system-arm \
    ovmf \
    busybox-static \
    && rm -rf /var/lib/apt/lists/*

# Network virtualization and SDN tooling (Open vSwitch).
RUN apt-get update && apt-get install -y \
    openvswitch-switch \
    openvswitch-common \
    iptables \
    dnsmasq \
    kmod \
    && rm -rf /var/lib/apt/lists/* && \
    mkdir -p \
      /var/run/openvswitch \
      /var/log/openvswitch \
      /etc/openvswitch \
      /usr/local/var/run/openvswitch \
      /usr/local/var/log/openvswitch

# ISO building, initramfs and archive tools; LUKS2 for the suites that create
# loopback-backed LUKS2 containers.
RUN apt-get update && apt-get install -y \
    xorriso \
    grub-efi-amd64-bin \
    grub-common \
    dosfstools \
    mtools \
    squashfs-tools \
    libarchive-tools \
    p7zip-full \
    cryptsetup \
    cryptsetup-bin \
    && rm -rf /var/lib/apt/lists/*

# Node.js, for the web console and its Playwright suite (test/integration/web):
# the official release archive pinned in scripts/tool-pins.sh, checked against
# its digest before it is unpacked into /usr/local. npm and npx come with it;
# nothing here uses yarn.
COPY scripts/tool-pins.sh /tmp/tool-pins.sh
RUN set -eu; \
    . /tmp/tool-pins.sh; \
    case "${TARGETARCH:-amd64}" in \
      amd64) arch=x64; sum="${NODE_SHA256_LINUX_AMD64}" ;; \
      arm64) arch=arm64; sum="${NODE_SHA256_LINUX_ARM64}" ;; \
      *) echo "no node pin for ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    f="node-${NODE_VERSION}-linux-${arch}.tar.xz"; \
    curl -fsSL -o "/tmp/${f}" "https://nodejs.org/dist/${NODE_VERSION}/${f}"; \
    echo "${sum}  /tmp/${f}" > /tmp/node.sha256; \
    sha256sum -c /tmp/node.sha256; \
    tar -xJf "/tmp/${f}" -C /usr/local --strip-components=1 --no-same-owner; \
    rm -f "/tmp/${f}" /tmp/node.sha256 /tmp/tool-pins.sh \
      /usr/local/CHANGELOG.md /usr/local/LICENSE /usr/local/README.md; \
    node -v; npm -v

# Playwright browser runtime libraries and fonts. The suite runs headless, so
# no X server.
RUN apt-get update && apt-get install -y \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    libatspi2.0-0 \
    libwayland-client0 \
    fonts-liberation \
    fonts-noto-color-emoji \
    libvpx7 \
    libopus0 \
    libharfbuzz0b \
    && rm -rf /var/lib/apt/lists/*

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=0

RUN mkdir -p \
      /var/run/swtpm \
      /var/lib/swtpm \
      /var/log/swtpm \
      /ms-playwright && \
    chmod 777 /var/run/swtpm /var/lib/swtpm /var/log/swtpm /ms-playwright && \
    echo -e "*\t-\tmemlock\tunlimited" >> /etc/security/limits.conf

RUN echo "=== Installation Verification ===" && \
    echo "Go: $(go version)" && \
    echo "Node: $(node -v)" && \
    echo "swtpm: $(swtpm --version 2>&1 | head -1)" && \
    echo "QEMU: $(qemu-system-x86_64 --version | head -1)" && \
    echo "OVS: $(ovs-vsctl --version | head -1)" && \
    echo "tpm2_startup: $(command -v tpm2_startup)" && \
    echo "cryptsetup: $(cryptsetup --version)"

# `make build-public-html` runs swag by this path.
COPY --from=tools /out-integration/swag /go/bin/swag
COPY build/docker/devcontainer/swtpm-provision.sh /usr/local/lib/devcontainer/swtpm-provision.sh
COPY build/docker/devcontainer/wait-for.sh /usr/local/lib/devcontainer/wait-for.sh
COPY build/docker/devcontainer/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# The source, last, so a code change rebuilds only this layer.
# build/docker/devcontainer/run-integration-tests.sh builds from /workspace.
COPY . /workspace
RUN git config --system --add safe.directory '*'
WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
