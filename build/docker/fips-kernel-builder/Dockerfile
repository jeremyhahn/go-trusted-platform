FROM alpine:3.22

# Install kernel build dependencies
RUN apk add --no-cache \
    build-base \
    bc \
    bison \
    flex \
    openssl \
    openssl-dev \
    elfutils-dev \
    linux-headers \
    perl \
    bash \
    wget \
    xz \
    findutils \
    gnupg \
    curl \
    ca-certificates \
    git

# Set working directory
WORKDIR /build

# Download kernel.org verification script
RUN wget -O /build/get-verified-tarball \
    https://git.kernel.org/pub/scm/linux/kernel/git/mricon/korg-helpers.git/plain/get-verified-tarball && \
    chmod +x /build/get-verified-tarball

# Copy build script
COPY build-fips-kernel.sh /build/
RUN chmod +x /build/build-fips-kernel.sh

# The options every platform kernel carries and the check that enforces them,
# shared with the virt kernel builder. "kernelconfig" is a named build context
# (docker build --build-context kernelconfig=../kernel-config): baked in, not
# mounted, because pkg/iso runs this image with only /output mounted.
COPY --from=kernelconfig platform-required.config require-config.sh /build/kernel-config/

# Set entrypoint
ENTRYPOINT ["/build/build-fips-kernel.sh"]
