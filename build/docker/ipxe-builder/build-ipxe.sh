#!/bin/bash
# Build the Trusted Platform iPXE binaries. Runs inside the ipxe-builder
# container; see the Makefile beside it for the host-side invocation.
#
# Inputs (environment):
#   IPXE_VERSION    upstream release tag without the v, e.g. 2.0.0
#   IPXE_SHA256     sha256 of the release tarball (fail-closed)
#   IPXE_TARGETS    space-separated build targets, e.g. bin-arm64-efi/snponly.efi
#   IPXE_CACHE_KEY  the key the caller derived from every build input,
#                   recorded in the manifest
# Directories (build/docker/run-builder.sh copies them with docker cp; a bind
# mount would be resolved on the Docker daemon's filesystem, which is not the
# checkout when the build runs in a CI job container):
#   /configs    iPXE config/local/*.h overrides, copied in
#   /output     artifacts + manifest.json, copied out when the build succeeds
#   /build/src  tarball cache, a named docker volume
set -euo pipefail
: "${IPXE_VERSION:?IPXE_VERSION is required}"
: "${IPXE_SHA256:?IPXE_SHA256 is required}"
: "${IPXE_CACHE_KEY:?IPXE_CACHE_KEY is required}"
TARGETS="${IPXE_TARGETS:-bin-arm64-efi/snponly.efi}"
OUT=/output
CFG=/configs
SRC=/build/src

mkdir -p "$SRC" "$OUT"
tarball="ipxe-${IPXE_VERSION}.tar.gz"
if [ ! -f "$SRC/$tarball" ]; then
    echo "downloading $tarball"
    wget -q -O "$SRC/$tarball.part" "https://github.com/ipxe/ipxe/archive/refs/tags/v${IPXE_VERSION}.tar.gz"
    mv "$SRC/$tarball.part" "$SRC/$tarball"
fi
echo "$IPXE_SHA256  $SRC/$tarball" | sha256sum -c - >/dev/null
echo "verified $tarball"

work=/build/work
rm -rf "$work"; mkdir -p "$work"
tar -C "$work" -xzf "$SRC/$tarball"
cd "$work/ipxe-${IPXE_VERSION}/src"

# Every header in /configs is an iPXE config/local override, applied by
# name (nap.h -> config/local/nap.h).
for h in "$CFG"/*.h; do
    [ -e "$h" ] || continue
    echo "config/local/$(basename "$h") <- $h"
    cp "$h" "config/local/$(basename "$h")"
done

# Every arm64 target is cross-built with the bare-metal toolchain; the host
# toolchain builds the ELF-to-PE converter iPXE runs at the end.
targets_json=""
for target in $TARGETS; do
    case "$target" in
        bin-arm64-efi/*) cross="aarch64-none-elf-" ;;
        *) echo "unsupported target $target (only bin-arm64-efi/* is built here)" >&2; exit 2 ;;
    esac
    echo "=== building $target"
    make -j"$(nproc)" "$target" CROSS="$cross" NO_WERROR=1 >/dev/null
    dir="$OUT/$(dirname "$target")"
    mkdir -p "$dir"
    cp "$target" "$dir/"
    (cd "$dir" && sha256sum "$(basename "$target")" > SHA256SUMS)
    size=$(stat -c %s "$target")
    echo "=== $target: $size bytes"
    targets_json="${targets_json:+$targets_json, }\"$target\""
done

cat > "$OUT/manifest.json" <<JSON
{
  "ipxe_version": "$IPXE_VERSION",
  "tarball_sha256": "$IPXE_SHA256",
  "cache_key": "$IPXE_CACHE_KEY",
  "targets": [$targets_json],
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
echo "done: $OUT/manifest.json"
