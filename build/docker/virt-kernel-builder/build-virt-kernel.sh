#!/bin/bash
# Build the aarch64 kernel for the QEMU virt stand-in of the Raspberry Pi
# factory image. Runs inside the virt-kernel-builder container; see the
# Makefile beside it for the host-side invocation.
#
# Inputs (environment):
#   KERNEL_VERSION    upstream stable release (Alpine's linux-lts version)
#   KERNEL_SHA256     sha256 of linux-$KERNEL_VERSION.tar.xz (fail-closed)
#   KERNEL_CACHE_KEY  the key the caller derived from every build input
#   KERNEL_LOCALVERSION  appended to the version (Alpine flavour naming)
#   KERNEL_CONFIG_ONLY  1 stops after the configuration is checked (no
#                     compile, no output): `make config-check`
# Baked into the image (the kernelconfig build context):
#   /build/kernel-config  platform-required.config + require-config.sh, shared
#                         with the fips kernel builder
# Mounts:
#   /configs   the Kconfig fragment (virt.config)   read-only
#   /output    artifacts + manifest.json
#   /build/src tarball cache (optional)
set -euo pipefail

: "${KERNEL_VERSION:?KERNEL_VERSION is required}"
: "${KERNEL_SHA256:?KERNEL_SHA256 is required}"
: "${KERNEL_CACHE_KEY:?KERNEL_CACHE_KEY is required}"
LOCALVERSION="${KERNEL_LOCALVERSION:--0-virt}"
FLAVOR="${KERNEL_FLAVOR:-virt}"
OUT=/output
CFG=/configs
SRC=/build/src

SHARED=/build/kernel-config

for f in "$CFG/virt.config" "$SHARED/platform-required.config" "$SHARED/require-config.sh"; do
    [ -r "$f" ] || { echo "missing builder input $f" >&2; exit 2; }
done

mkdir -p "$SRC" "$OUT"
tarball="linux-${KERNEL_VERSION}.tar.xz"
if [ ! -f "$SRC/$tarball" ]; then
    echo "downloading $tarball"
    wget -q -O "$SRC/$tarball.part" "https://cdn.kernel.org/pub/linux/kernel/v6.x/$tarball"
    mv "$SRC/$tarball.part" "$SRC/$tarball"
fi
echo "$KERNEL_SHA256  $SRC/$tarball" | sha256sum -c - >/dev/null
echo "verified $tarball"

work=/build/work
rm -rf "$work"; mkdir -p "$work"
tar -C "$work" -xJf "$SRC/$tarball"
cd "$work/linux-${KERNEL_VERSION}"

# --- Configuration --------------------------------------------------------
# arm64 defconfig, then the stand-in's fragment and the options every
# platform kernel carries. merge_config.sh keeps every fragment line that
# Kconfig accepts; require-config.sh fails the build on any it dropped, so an
# unmet dependency is a build failure, not a silent downgrade.
make -s ARCH=arm64 defconfig
./scripts/kconfig/merge_config.sh -m .config "$CFG/virt.config" "$SHARED/platform-required.config" >/dev/null
./scripts/config --set-str CONFIG_LOCALVERSION "$LOCALVERSION"
./scripts/config --disable CONFIG_LOCALVERSION_AUTO
make -s ARCH=arm64 olddefconfig
"$SHARED/require-config.sh" .config "$CFG/virt.config" "$SHARED/platform-required.config"
echo "configuration carries $CFG/virt.config and $SHARED/platform-required.config"
if [ "${KERNEL_CONFIG_ONLY:-0}" = 1 ]; then
    echo "KERNEL_CONFIG_ONLY=1: configuration checked, nothing built"
    exit 0
fi

# --- Build ----------------------------------------------------------------
echo "=== building linux-${KERNEL_VERSION}${LOCALVERSION} for arm64"
make -s ARCH=arm64 -j"$(nproc)" Image.gz modules
KVER=$(make -s ARCH=arm64 kernelrelease)
echo "=== kernel release $KVER"

# --- Package (the layout pkg/installer's media kernel install reads) ------
dest="$OUT/$FLAVOR"
rm -rf "$dest"; mkdir -p "$dest"
cp arch/arm64/boot/Image.gz "$dest/vmlinuz-$FLAVOR"
modtmp="$work/modules"
rm -rf "$modtmp"; mkdir -p "$modtmp"
make -s ARCH=arm64 modules_install INSTALL_MOD_PATH="$modtmp" INSTALL_MOD_STRIP=1
# The modules tarball unpacks at the target root; the build/source symlinks
# point into the container and are not shipped.
rm -f "$modtmp/lib/modules/$KVER/build" "$modtmp/lib/modules/$KVER/source"
tar -C "$modtmp" -czf "$dest/modules-$FLAVOR.tar.gz" "lib/modules/$KVER"
cp System.map "$dest/System.map-$FLAVOR"
cp .config "$dest/config-$FLAVOR"
echo "$KVER" > "$dest/kernel-version.txt"
(cd "$dest" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)

cat > "$OUT/manifest.json" <<JSON
{
  "kernel_version": "$KERNEL_VERSION",
  "kernel_release": "$KVER",
  "tarball_sha256": "$KERNEL_SHA256",
  "cache_key": "$KERNEL_CACHE_KEY",
  "flavor": "$FLAVOR",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
echo "done: $OUT/manifest.json ($(stat -c %s "$dest/vmlinuz-$FLAVOR") bytes kernel)"
