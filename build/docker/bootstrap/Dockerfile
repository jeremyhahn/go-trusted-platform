# Trusted Platform PXE boot container.

FROM alpine:3.22

# Samba, its tools and supervisor.
RUN apk add --no-cache samba-server samba-common-tools supervisor

# PXE boot server binary
COPY pxeboot /usr/local/bin/pxeboot

# The entrypoint validates the env, prepares samba's state and execs supervisord.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY pxeboot-env.sh /usr/local/bin/pxeboot-env.sh

# Samba: anonymous read-only [boot] share over /data
COPY smb.conf /etc/samba/smb.conf

# supervisord: pxeboot + smbd + nmbd under one PID 1
COPY supervisord.conf /etc/supervisor/supervisord.conf

RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/pxeboot

# Ports: DHCP 67, TFTP 69, NetBIOS 137-139, SMB 445 (BMC virtual media), HTTP 8080.
EXPOSE 67/udp 69/udp 137/udp 138/udp 139/tcp 445/tcp 8080/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
