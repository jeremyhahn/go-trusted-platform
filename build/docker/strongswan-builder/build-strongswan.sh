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
#   APK_KEY_NAME        file name of the apk signing key in /keys
#                       (<name>.rsa, with <name>.rsa.pub beside it)
# Mounts:
#   /keys        the apk signing key pair                 read-only
#   /output      <arch>/ apks, APKINDEX, SHA256SUMS, manifest.json; keys/
#   /build/src   tarball cache (optional)
set -euo pipefail

: "${STRONGSWAN_VERSION:?STRONGSWAN_VERSION is required}"
: "${STRONGSWAN_SHA256:?STRONGSWAN_SHA256 is required}"
: "${STRONGSWAN_SIGNER:?STRONGSWAN_SIGNER is required}"
: "${STRONGSWAN_PLUGINS:?STRONGSWAN_PLUGINS is required}"
: "${APK_KEY_NAME:?APK_KEY_NAME is required}"

SRC=/build/src
KEYRING=/build/strongswan-release-key.gpg
PKG=trusted-platform-strongswan
ARCH=$(apk --print-arch)
tarball="strongswan-${STRONGSWAN_VERSION}.tar.bz2"

for f in "/keys/$APK_KEY_NAME" "/keys/$APK_KEY_NAME.pub"; do
    [ -r "$f" ] || { echo "missing apk signing key $f" >&2; exit 2; }
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
# abuild refuses to run as root, so the package is built by the unprivileged
# builder user. The aport sits under a directory named "platform", which
# abuild uses as the repository name in its output path.
home=/home/builder
aport="$home/aports/platform/$PKG"
rm -rf "$home/aports" "$home/packages" "$home/.abuild"
mkdir -p "$aport" "$home/.abuild" /var/cache/distfiles
cp /build/aport/* "$aport/"
sed -i \
    -e "s|@STRONGSWAN_VERSION@|$STRONGSWAN_VERSION|" \
    -e "s|@STRONGSWAN_PLUGINS@|$STRONGSWAN_PLUGINS|" \
    "$aport/APKBUILD"
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

su builder -s /bin/sh -c "cd '$aport' && abuild checksum && abuild -d -P '$home/packages'"

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
  "package": "$PKG",
  "strongswan_version": "$STRONGSWAN_VERSION",
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
