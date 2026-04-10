FROM alpine:3.22

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    perl \
    linux-headers \
    wget \
    ca-certificates

# Set working directory
WORKDIR /build

# Copy build script
COPY build-fips-provider.sh /build/
RUN chmod +x /build/build-fips-provider.sh

# Set entrypoint
ENTRYPOINT ["/build/build-fips-provider.sh"]
