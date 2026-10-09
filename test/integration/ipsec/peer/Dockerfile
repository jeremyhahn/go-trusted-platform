# The root filesystem of one IPsec peer in the ipsec integration suite:
# Alpine 3.22 (musl), as on a node, with the trusted-platform-strongswan
# apks from build/docker/strongswan-builder installed through apk with their
# signatures checked against the builder's published key -- the same path a
# node's installer takes.
#
# Built per architecture by `make ipsec-test-inputs` with the builder output
# as the named build context "apks", then exported to a tarball the suite
# unpacks per peer. Nothing here starts charon: the suite starts it with the
# packaged OpenRC service inside the peer's network namespace.
FROM alpine:3.22

COPY --from=apks keys/ /etc/apk/keys/
COPY --from=apks x86_64/ /repo/platform/x86_64/
COPY --from=apks aarch64/ /repo/platform/aarch64/

# The platform daemon's account: the owner of charon's VICI socket
# (CHARON_VICI_USER and CHARON_VICI_GROUP default to platformd:platform).
RUN addgroup -S platform && adduser -S -D -H -h /var/empty -s /sbin/nologin -G platform platformd

# The two packages with their OpenRC services are what a node installs for the
# overlay (pkg/iso PlatformPackages): charon, and the module host that serves
# the go-xkms PKCS#11 module to it. p11-kit-server carries p11-kit-client.so,
# the PKCS#11 module charon loads (docs/sdn/engineering.md, "PKCS#11 on
# musl"); opensc's pkcs11-tool provisions the token through it; openrc runs
# the packaged services.
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
