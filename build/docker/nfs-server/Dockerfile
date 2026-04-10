FROM debian:bookworm

RUN apt-get update && apt-get install -y \
    nfs-kernel-server \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /exports \
    && chmod 755 /exports

COPY exports /etc/exports

EXPOSE 111/tcp 111/udp 2049/tcp 2049/udp 32769/udp 32803/tcp

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

