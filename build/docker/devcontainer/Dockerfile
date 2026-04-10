# Development Container for go-trusted-platform
# This container provides all tooling needed for development, testing, and CI/CD
#
# Usage:
#   docker build -t go-trusted-platform-dev .
#   docker run --rm -it --privileged -v $(pwd):/workspace go-trusted-platform-dev
#
# For integration tests with KVM acceleration:
#   docker run --rm -it --privileged --device /dev/kvm -v $(pwd):/workspace go-trusted-platform-dev

ARG BASE_IMAGE="golang:1.26-bookworm"

FROM ${BASE_IMAGE}

LABEL maintainer="Jeremy Hahn <mail@jeremyhahn.com>"
LABEL description="Development container for go-trusted-platform with TPM, QEMU, and security tooling"

# Build arguments
ARG NVM_VERSION=v0.39.5
ARG NODE_VERSION=21.1.0
ARG QEMU_VERSION=8.2.0

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/go
ENV PATH="/usr/local/go/bin:${GOPATH}/bin:${PATH}"

SHELL ["/bin/bash", "-c"]

# =============================================================================
# Core system packages and build tools
# =============================================================================
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    # Build essentials
    build-essential \
    gcc \
    g++ \
    make \
    pkg-config \
    autoconf \
    automake \
    libtool \
    # Development tools
    git \
    curl \
    wget \
    vim \
    nano \
    jq \
    tree \
    htop \
    # Networking tools
    iproute2 \
    iputils-ping \
    dnsutils \
    netcat-openbsd \
    tcpdump \
    # SSL/TLS libraries
    libssl-dev \
    ca-certificates \
    openssl \
    gnutls-bin \
    # Compression
    xz-utils \
    zstd \
    # Process management
    procps \
    psmisc \
    supervisor \
    # Shell utilities
    bash-completion \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# TPM 2.0 Software Stack and swtpm (Software TPM)
# =============================================================================
RUN apt-get update && apt-get install -y \
    # TPM 2.0 tools and libraries
    tpm2-tools \
    tpm2-abrmd \
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
    # Software TPM emulator
    swtpm \
    swtpm-tools \
    libtpms0 \
    # TPM PKCS#11 interface
    libtpm2-pkcs11-1 \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# PKCS#11 / HSM / Smart Card tooling
# =============================================================================
RUN apt-get update && apt-get install -y \
    opensc \
    opensc-pkcs11 \
    libsofthsm2 \
    softhsm2 \
    pcscd \
    libpcsclite-dev \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# FIDO2 / Yubikey tooling
# =============================================================================
RUN apt-get update && apt-get install -y \
    yubikey-manager \
    libu2f-udev \
    libfido2-dev \
    fido2-tools \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# QEMU and OVMF for VM-based integration tests
# =============================================================================
RUN apt-get update && apt-get install -y \
    qemu-system-x86 \
    qemu-utils \
    qemu-efi-aarch64 \
    ovmf \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# Build QEMU with CanoKey support for FIDO2 emulation
# This provides qemu-system-x86_64-canokey binary alongside standard QEMU
# =============================================================================

# Install QEMU build dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    ninja-build \
    python3 \
    python3-pip \
    python3-venv \
    libglib2.0-dev \
    libfdt-dev \
    libpixman-1-dev \
    zlib1g-dev \
    libgtk-3-dev \
    libsdl2-dev \
    libspice-server-dev \
    libusb-1.0-0-dev \
    libusbredirparser-dev \
    libcap-ng-dev \
    libattr1-dev \
    libseccomp-dev \
    libaio-dev \
    libcurl4-gnutls-dev \
    libnuma-dev \
    libepoxy-dev \
    libgbm-dev \
    libdrm-dev \
    libvirglrenderer-dev \
    libslirp-dev \
    flex \
    bison \
    && rm -rf /var/lib/apt/lists/*

# Build libcanokey-qemu
RUN git clone --recursive https://github.com/canokeys/canokey-qemu /tmp/canokey-qemu && \
    cd /tmp/canokey-qemu && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    rm -rf /tmp/canokey-qemu

# Build QEMU with CanoKey support
RUN export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH && \
    cd /tmp && \
    curl -sSL "https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz" -o qemu.tar.xz && \
    tar xf qemu.tar.xz && \
    cd qemu-${QEMU_VERSION} && \
    ./configure \
        --prefix=/usr/local \
        --target-list=x86_64-softmmu \
        --enable-kvm \
        --enable-canokey \
        --enable-slirp \
        --enable-usb-redir \
        --enable-libusb \
        --enable-virtfs \
        --enable-spice \
        --enable-gtk \
        --enable-sdl \
        --enable-opengl \
        --enable-virglrenderer \
        --disable-docs && \
    make -j$(nproc) && \
    cp build/qemu-system-x86_64 /usr/local/bin/qemu-system-x86_64-canokey && \
    rm -rf /tmp/qemu*

# =============================================================================
# Secure Boot / UEFI tooling
# =============================================================================
RUN apt-get update && apt-get install -y \
    efitools \
    sbsigntool \
    pesign \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# Network virtualization and SDN tooling (Open vSwitch)
# =============================================================================
RUN apt-get update && apt-get install -y \
    bridge-utils \
    vde2 \
    # Open vSwitch for SDN integration tests
    openvswitch-switch \
    openvswitch-common \
    iptables \
    net-tools \
    dnsmasq \
    kmod \
    && rm -rf /var/lib/apt/lists/*

# Create OVS directories
RUN mkdir -p \
    /var/run/openvswitch \
    /var/log/openvswitch \
    /etc/openvswitch \
    /usr/local/var/run/openvswitch \
    /usr/local/var/log/openvswitch

# =============================================================================
# ISO building and initramfs manipulation tools
# =============================================================================
RUN apt-get update && apt-get install -y \
    # ISO creation and manipulation
    xorriso \
    genisoimage \
    grub-efi-amd64-bin \
    grub-common \
    dosfstools \
    mtools \
    # Initramfs and archive tools
    cpio \
    squashfs-tools \
    libarchive-tools \
    p7zip-full \
    # File type detection
    file \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# Install Go development tools
# =============================================================================
RUN go install github.com/swaggo/swag/cmd/swag@latest && \
    go install golang.org/x/tools/gopls@latest && \
    go install github.com/go-delve/delve/cmd/dlv@latest && \
    go install honnef.co/go/tools/cmd/staticcheck@latest && \
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# =============================================================================
# Install Node.js via nvm (for web dashboard builds)
# =============================================================================
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/${NVM_VERSION}/install.sh | bash && \
    export NVM_DIR="$HOME/.nvm" && \
    [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" && \
    nvm install ${NODE_VERSION} && \
    nvm use ${NODE_VERSION} && \
    nvm alias default ${NODE_VERSION} && \
    ln -sf "$NVM_DIR/versions/node/$(nvm version)/bin/node" /usr/local/bin/node && \
    ln -sf "$NVM_DIR/versions/node/$(nvm version)/bin/npm" /usr/local/bin/npm && \
    ln -sf "$NVM_DIR/versions/node/$(nvm version)/bin/npx" /usr/local/bin/npx && \
    npm install --global yarn && \
    ln -sf "$NVM_DIR/versions/node/$(nvm version)/bin/yarn" /usr/local/bin/yarn && \
    node -v && npm -v && yarn -v

# =============================================================================
# Install Playwright browser dependencies for E2E testing
# =============================================================================
RUN apt-get update && apt-get install -y \
    # Browser runtime dependencies
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
    # Font support
    fonts-liberation \
    fonts-noto-color-emoji \
    # Media codecs
    libvpx7 \
    libopus0 \
    libharfbuzz0b \
    # X11 dependencies for headless mode
    xvfb \
    x11-utils \
    x11-xserver-utils \
    && rm -rf /var/lib/apt/lists/*

# Environment variables for Playwright
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=0

# =============================================================================
# Create directories and set permissions
# =============================================================================
RUN mkdir -p \
    /var/run/swtpm \
    /var/lib/swtpm \
    /var/log/swtpm \
    /workspace \
    /go \
    /ms-playwright \
    && chmod 777 /var/run/swtpm /var/lib/swtpm /var/log/swtpm /ms-playwright

# Set memory limits for TPM operations
RUN echo "*\t-\tmemlock\tunlimited" >> /etc/security/limits.conf

# =============================================================================
# Setup working directory
# =============================================================================
WORKDIR /workspace

# =============================================================================
# Verify installations
# =============================================================================
RUN echo "=== Installation Verification ===" && \
    echo "Go: $(go version)" && \
    echo "Node: $(node -v)" && \
    echo "npm: $(npm -v)" && \
    echo "Yarn: $(yarn -v)" && \
    echo "swtpm: $(swtpm --version 2>&1 | head -1)" && \
    echo "QEMU: $(qemu-system-x86_64 --version | head -1)" && \
    echo "QEMU-CanoKey: $(/usr/local/bin/qemu-system-x86_64-canokey --version | head -1)" && \
    echo "OVS: $(ovs-vsctl --version | head -1)" && \
    echo "xorriso: $(xorriso --version 2>&1 | head -1)" && \
    echo "tpm2_startup: $(which tpm2_startup)" && \
    echo "OVMF: $(ls -la /usr/share/OVMF/OVMF_CODE*.fd 2>/dev/null | head -2 || echo 'OVMF installed')" && \
    echo "Playwright: Browser dependencies installed" && \
    echo "================================="

# =============================================================================
# Default entrypoint
# =============================================================================
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
