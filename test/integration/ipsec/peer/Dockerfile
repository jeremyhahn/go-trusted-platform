# One IPsec peer's root filesystem: Alpine with the trusted-platform-strongswan apks, signature-checked as on a node.
FROM alpine:3.22

COPY --from=apks keys/ /etc/apk/keys/
COPY --from=apks x86_64/ /repo/platform/x86_64/
COPY --from=apks aarch64/ /repo/platform/aarch64/

# The two packages a node installs for the overlay, p11-kit-client.so for charon, pkcs11-tool and openrc.
RUN apk add --no-cache --repository /repo/platform \
        trusted-platform-strongswan \
        trusted-platform-strongswan-openrc \
        trusted-platform-p11-host \
        trusted-platform-p11-host-openrc \
        iproute2 \
        opensc \
        openrc \
        p11-kit-server \
    && rm -rf /repo \
    && sed -i -e 's/^#\?rc_sys=.*/rc_sys="docker"/' -e 's/^#\?rc_provide=.*/rc_provide="loopback net"/' /etc/rc.conf
