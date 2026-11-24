# go-trusted-platform devcontainer: one Dockerfile, the shipped stages built from base.

ARG GO_IMAGE
# Build-time module and tool downloads go through this proxy.
ARG GO_BUILD_PROXY=https://proxy.golang.org,direct

# ---------------------------------------------------------------------------
FROM ${GO_IMAGE} AS tools
ARG GO_BUILD_PROXY
ARG TARGETARCH
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOPROXY=${GO_BUILD_PROXY} GOBIN=/out
COPY scripts/tool-pins.sh /tmp/tool-pins.sh
# swag builds from its build/tools-src module; the Makefile builds golangci-lint, actionlint and gosec the same way.
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
    curl -fsSL --retry 12 --retry-delay 20 --retry-max-time 300 -o "/tmp/${f}" "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/${f}"; \
    echo "${sum}  /tmp/${f}" > /tmp/trivy.sha256; \
    sha256sum -c /tmp/trivy.sha256; \
    tar -xzf "/tmp/${f}" -C /out trivy; \
    rm -f "/tmp/${f}"

# github.com/jeremyhahn/* modules resolve through git, which the golang image carries.
FROM ${GO_IMAGE} AS modules
ARG GO_BUILD_PROXY
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOMODCACHE=/gomodcache GOPROXY=${GO_BUILD_PROXY}
WORKDIR /src

# Download the module caches in their own layer.
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
# GOTOOLCHAIN=local: a go.mod asking for a newer Go fails instead of downloading one.
ENV GOTOOLCHAIN=local \
    CGO_ENABLED=1 \
    GOFLAGS=-mod=readonly \
    GOMODCACHE=/gomodcache \
    GOCACHE=/gocache
# cpio for pkg/diskimage/netboot; libssl-dev for go-tpm-tools' simulator.
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
# Open the empty build cache for writing to any uid.
RUN install -d -m 0777 /gocache
# Nothing fetches a module at run time (devcontainer.md §4).
ENV GOPROXY=off

# ---------------------------------------------------------------------------
FROM base AS toolchain
ARG DEBIAN_FRONTEND=noninteractive
# Usable as any non-root uid; GOTMPDIR sits beside the build cache.
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

# The suite runs as root, privileged: it starts Open vSwitch, swtpm and qemu, and attaches loopback LUKS2 volumes.
FROM base AS integration
ARG DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
# The Alpine package index checksum the content tag hashes (scripts/apk-index-sum.sh).
ARG APK_INDEX_SUM
SHELL ["/bin/bash", "-c"]

# Networking and process tools the suites and the entrypoint call.
RUN apt-get update && apt-get install -y \
    curl jq \
    iproute2 iputils-ping dnsutils netcat-openbsd \
    procps psmisc \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# chrony for the ntp suite.
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

# QEMU and OVMF for the VM suites; busybox-static for the Secure Boot initramfs test.
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

# ISO, initramfs and archive tools; LUKS2 for the loopback LUKS2 suites.
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

# Node.js from its release archive, pinned and checked in scripts/tool-pins.sh.
COPY scripts/tool-pins.sh /tmp/tool-pins.sh
RUN set -eu; \
    . /tmp/tool-pins.sh; \
    case "${TARGETARCH:-amd64}" in \
      amd64) arch=x64; sum="${NODE_SHA256_LINUX_AMD64}" ;; \
      arm64) arch=arm64; sum="${NODE_SHA256_LINUX_ARM64}" ;; \
      *) echo "no node pin for ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    f="node-${NODE_VERSION}-linux-${arch}.tar.xz"; \
    curl -fsSL --retry 12 --retry-delay 20 --retry-max-time 300 -o "/tmp/${f}" "https://nodejs.org/dist/${NODE_VERSION}/${f}"; \
    echo "${sum}  /tmp/${f}" > /tmp/node.sha256; \
    sha256sum -c /tmp/node.sha256; \
    tar -xJf "/tmp/${f}" -C /usr/local --strip-components=1 --no-same-owner; \
    rm -f "/tmp/${f}" /tmp/node.sha256 /tmp/tool-pins.sh \
      /usr/local/CHANGELOG.md /usr/local/LICENSE /usr/local/README.md; \
    node -v; npm -v

# Playwright browser runtime libraries and fonts.
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
COPY . /workspace
RUN git config --system --add safe.directory '*'
WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]

# The image `make integration-test` and CI's integration legs run.
FROM integration AS integration-legs
ARG IT_BUILD_TAGS
RUN --mount=type=cache,id=go-trusted-platform-it-gocache,target=/buildcache,sharing=locked \
    set -eu; \
    : "${IT_BUILD_TAGS:?pass the Makefile TEST_BUILD_TAGS: make docker-build-it}"; \
    GOFLAGS="-mod=readonly -buildvcs=false" GOWORK=off \
      bash build/docker/devcontainer/run-integration-tests.sh warm "${IT_BUILD_TAGS}" /buildcache
