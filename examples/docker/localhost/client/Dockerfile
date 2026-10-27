FROM debian:bookworm

# Install required packages
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    swtpm \
    swtpm-tools \
    softhsm2 \
    && rm -rf /var/lib/apt/lists/*

# Create tpadm user
RUN useradd -m -u 1000 -s /bin/bash tpadm

# Setup directories
RUN mkdir -p /opt/trusted-platform/trusted-data && \
    chown -R tpadm:tpadm /opt/trusted-platform

# Copy the platform binary
COPY platformd /usr/local/bin/platformd
RUN chmod +x /usr/local/bin/platformd

# Copy public_html
COPY public_html /opt/trusted-platform/public_html

# Copy configuration
COPY config.yaml /opt/trusted-platform/config.yaml

# Copy the bounded readiness helper (wait_for) and the entrypoint script
COPY wait-for.sh /usr/local/lib/wait-for.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Setup SoftHSM2
RUN mkdir -p /opt/trusted-platform/trusted-data/platform/keystore/pkcs11/softhsm/tokens && \
    chown -R tpadm:tpadm /opt/trusted-platform

USER tpadm
WORKDIR /opt/trusted-platform

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]