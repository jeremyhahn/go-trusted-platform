#!/bin/bash
# Build the Trusted Platform strongSwan apks for this container's
# architecture. Runs inside the strongswan-builder container; see the
# Makefile beside it for the host-side invocation.
#
# Inputs (environment):
#   STRONGSWAN_VERSION  upstream release, e.g. 6.0.7
#   STRONGSWAN_SHA256   sha256 of strongswan-$STRONGSWAN_VERSION.tar.bz2
#   STRONGSWAN_SIGNER   fingerprint of the primary key that must have signed
#                       the tarball (the strongSwan release signing key)
#   STRONGSWAN_PLUGINS  the exact plugin set charon is built with
#   P11_HOST_VERSION    apk version of trusted-platform-p11-host: the go-xkms
#                       release its module is built from, as an apk version
#   APK_KEY_NAME        file name of the apk signing key in /keys
#                       (<name>.rsa, with <name>.rsa.pub beside it)
# Directories and files (build/docker/run-builder.sh copies them with docker
# cp; a bind mount would be resolved on the Docker daemon's filesystem, which
# is not the checkout when the build runs in a CI job container):
#   /keys        the apk signing key pair, copied in
#   /build/modulehost.tar
#                the module host's root filesystem (modulehost/Dockerfile,
#                exported by `make ipsec-module-host`), copied in
#   /output      <arch>/ apks, APKINDEX, SHA256SUMS, manifest.json; keys/,
#                copied out when the build succeeds
#   /build/src   tarball cache, a named docker volume
set -euo pipefail

: "${STRONGSWAN_VERSION:?STRONGSWAN_VERSION is required}"
: "${STRONGSWAN_SHA256:?STRONGSWAN_SHA256 is required}"
: "${STRONGSWAN_SIGNER:?STRONGSWAN_SIGNER is required}"
: "${STRONGSWAN_PLUGINS:?STRONGSWAN_PLUGINS is required}"
: "${APK_KEY_NAME:?APK_KEY_NAME is required}"
: "${P11_HOST_VERSION:?P11_HOST_VERSION is required}"

SRC=/build/src
KEYRING=/build/strongswan-release-key.gpg
PKG=trusted-platform-strongswan
HOST_PKG=trusted-platform-p11-host
MODULE_HOST=/build/modulehost.tar
ARCH=$(apk --print-arch)
tarball="strongswan-${STRONGSWAN_VERSION}.tar.bz2"

for f in "/keys/$APK_KEY_NAME" "/keys/$APK_KEY_NAME.pub" "$MODULE_HOST"; do
    [ -r "$f" ] || { echo "missing input $f" >&2; exit 2; }
done

# --- Fetch -------------------------------------------------------------------
# A release moves under old/<major>.x/ once a newer one is published, so a
# pinned version is looked up in both places.
fetch() {
    local name="$1" url
    [ -f "$SRC/$name" ] && return 0
    for url in "https://download.strongswan.org/$name" "https://download.strongswan.org/old/${STRONGSWAN_VERSION%%.*}.x/$name"; do
        if wget -q -O "$SRC/$name.part" "$url"; then
            mv "$SRC/$name.part" "$SRC/$name"
            return 0
        fi
    done
    rm -f "$SRC/$name.part"
    echo "cannot download $name" >&2
    exit 2
}
mkdir -p "$SRC"
fetch "$tarball"
fetch "$tarball.sig"

# --- Verify (fail-closed) ----------------------------------------------------
# The signature must be good AND made by the pinned primary key: gpgv accepts
# any key in the keyring, so the VALIDSIG status line's primary-key
# fingerprint (its last field) is compared with the pin.
status=$(gpgv --status-fd 1 --keyring "$KEYRING" "$SRC/$tarball.sig" "$SRC/$tarball" 2>/dev/null) || {
    echo "$tarball: signature verification FAILED" >&2
    exit 4
}
signer=$(printf '%s\n' "$status" | awk '$2 == "VALIDSIG" { print $NF }')
if [ "$signer" != "$STRONGSWAN_SIGNER" ]; then
    echo "$tarball: signed by '$signer', expected $STRONGSWAN_SIGNER" >&2
    exit 4
fi
echo "$STRONGSWAN_SHA256  $SRC/$tarball" | sha256sum -c - >/dev/null || {
    echo "$tarball: sha256 does not match $STRONGSWAN_SHA256" >&2
    exit 4
}
echo "verified $tarball (signer $signer, sha256 $STRONGSWAN_SHA256)"

# --- abuild ------------------------------------------------------------------
# abuild refuses to run as root, so the packages are built by the unprivileged
# builder user. The aports sit under a directory named "platform", which
# abuild uses as the repository name in its output path; both land in the same
# repository and APKINDEX.
home=/home/builder
rm -rf "$home/aports" "$home/packages" "$home/.abuild"
mkdir -p "$home/aports/platform" "$home/.abuild" /var/cache/distfiles

# stage_aport copies an aport's files into the repository and substitutes the
# builder's pins for the placeholders in its APKBUILD and settings files.
stage_aport() {
    local pkg="$1" from="$2" aport="$home/aports/platform/$1"
    mkdir -p "$aport"
    cp "$from"/* "$aport/"
    find "$aport" \( -name APKBUILD -o -name '*.conf' \) -exec sed -i \
        -e "s|@STRONGSWAN_VERSION@|$STRONGSWAN_VERSION|" \
        -e "s|@STRONGSWAN_PLUGINS@|$STRONGSWAN_PLUGINS|" \
        -e "s|@P11_HOST_VERSION@|$P11_HOST_VERSION|" {} +
}
stage_aport "$PKG" /build/aport
stage_aport "$HOST_PKG" /build/aport-p11-host
cp "$MODULE_HOST" "$home/aports/platform/$HOST_PKG/modulehost.rootfs"
cp "$SRC/$tarball" /var/cache/distfiles/
cp "/keys/$APK_KEY_NAME" "/keys/$APK_KEY_NAME.pub" "$home/.abuild/"
chmod 600 "$home/.abuild/$APK_KEY_NAME"
cat > "$home/.abuild/abuild.conf" <<EOF
PACKAGER="Trusted Platform <packager@trusted-platform.invalid>"
PACKAGER_PRIVKEY="$home/.abuild/$APK_KEY_NAME"
EOF
# apk index (run by abuild as the builder user) checks every package's
# signature against /etc/apk/keys, so the public key must be world-readable
# there whatever mode it was mounted with.
install -m 644 "/keys/$APK_KEY_NAME.pub" /etc/apk/keys/
chown -R builder:builder "$home" /var/cache/distfiles

for pkg in "$PKG" "$HOST_PKG"; do
    su builder -s /bin/sh -c "cd '$home/aports/platform/$pkg' && abuild checksum && abuild -d -P '$home/packages'"
done

# --- Output ------------------------------------------------------------------
dest="/output/$ARCH"
rm -rf "$dest"
mkdir -p "$dest" /output/keys
cp "$home/packages/platform/$ARCH/"* "$dest/"
install -m 644 "/keys/$APK_KEY_NAME.pub" /output/keys/
apks=$(cd "$dest" && ls ./*.apk | sed 's|^\./||' | sort | awk '{ printf "%s\"%s\"", (NR > 1 ? ", " : ""), $0 }')
plugins=$(printf '%s\n' $STRONGSWAN_PLUGINS | awk '{ printf "%s\"%s\"", (NR > 1 ? ", " : ""), $0 }')
cat > "$dest/manifest.json" <<JSON
{
  "packages": ["$PKG", "$HOST_PKG"],
  "strongswan_version": "$STRONGSWAN_VERSION",
  "p11_host_version": "$P11_HOST_VERSION",
  "arch": "$ARCH",
  "tarball_sha256": "$STRONGSWAN_SHA256",
  "tarball_signer": "$signer",
  "apk_signing_key": "$APK_KEY_NAME.pub",
  "plugins": [$plugins],
  "apks": [$apks],
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
(cd "$dest" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
echo "done: $dest"
ls -l "$dest"
