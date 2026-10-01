#!/bin/bash
# Build the Trusted Platform U-Boot binaries. Runs inside the uboot-builder
# container; see the Makefile beside it for the host-side invocation.
#
# Inputs (environment):
#   UBOOT_VERSION     upstream release, e.g. 2026.07
#   UBOOT_SHA256      sha256 of u-boot-$UBOOT_VERSION.tar.bz2 (fail-closed)
#   UBOOT_CACHE_KEY   the key the caller derived from every build input; it is
#                     recorded in the manifest so a later run can prove the
#                     output matches its inputs without rebuilding
#   UBOOT_OWNER_GUID  SignatureOwner GUID written into the PK/KEK/db lists
# Mounts:
#   /keys     PK.crt KEK.crt DB.crt (PEM or DER)   read-only
#   /configs  Kconfig fragments + tpm-soft-spi.dts  read-only
#   /output   per-board artifacts + manifest.json
#   /build/src  tarball cache (optional)
set -euo pipefail

: "${UBOOT_VERSION:?UBOOT_VERSION is required}"
: "${UBOOT_SHA256:?UBOOT_SHA256 is required}"
: "${UBOOT_CACHE_KEY:?UBOOT_CACHE_KEY is required}"
: "${UBOOT_OWNER_GUID:?UBOOT_OWNER_GUID is required}"
BOARDS="${UBOOT_BOARDS:-rpi_arm64 qemu_arm64}"
OUT=/output
KEYS=/keys
CFG=/configs
SRC=/build/src

EFI_GLOBAL_VARIABLE_GUID=8be4df61-93ca-11d2-aa0d-00e098032b8c
EFI_IMAGE_SECURITY_DATABASE_GUID=d719b2cb-3d3a-4596-a3bc-dad00e67656f

for f in PK.crt KEK.crt DB.crt; do
    [ -r "$KEYS/$f" ] || { echo "missing Secure Boot certificate $KEYS/$f" >&2; exit 2; }
done
for f in common-efi.config rpi_arm64-tpm.config qemu_arm64-tpm.config tpm-soft-spi.dts; do
    [ -r "$CFG/$f" ] || { echo "missing builder input $CFG/$f" >&2; exit 2; }
done

mkdir -p "$SRC" "$OUT"
tarball="u-boot-${UBOOT_VERSION}.tar.bz2"
if [ ! -f "$SRC/$tarball" ]; then
    echo "downloading $tarball"
    wget -q -O "$SRC/$tarball.part" "https://ftp.denx.de/pub/u-boot/$tarball"
    mv "$SRC/$tarball.part" "$SRC/$tarball"
fi
echo "$UBOOT_SHA256  $SRC/$tarball" | sha256sum -c - >/dev/null
echo "verified $tarball"

work=/build/work
rm -rf "$work"; mkdir -p "$work"
tar -C "$work" -xjf "$SRC/$tarball"
srctree="$work/u-boot-${UBOOT_VERSION}"
cd "$srctree"

# --- Local patches --------------------------------------------------------
# Applied in name order; each is a cache-key input (see the Makefile beside
# this script and pkg/diskimage/uboot.CacheKey), so a changed patch is a new
# build. A patch that no longer applies fails the build rather than being
# skipped: a binary built without it is not the binary the platform tested.
for p in /patches/*.patch; do
    [ -e "$p" ] || continue
    echo "applying $(basename "$p")"
    patch -p1 --no-backup-if-mismatch < "$p"
done

# --- Secure Boot variable preseed -------------------------------------------
# U-Boot's efi_var_seed.S incbins $(srctree)/$(CONFIG_EFI_VAR_SEED_FILE), so the
# store is created in the source root. Variables carry NV|BS|RT|AT exactly as
# an authenticated SetVariable would have written them; the preseed path
# trusts them because they were compiled in.
python3 /build/mkesl.py --cert "$KEYS/PK.crt"  --owner "$UBOOT_OWNER_GUID" --out "$work/PK.esl"
python3 /build/mkesl.py --cert "$KEYS/KEK.crt" --owner "$UBOOT_OWNER_GUID" --out "$work/KEK.esl"
python3 /build/mkesl.py --cert "$KEYS/DB.crt"  --owner "$UBOOT_OWNER_GUID" --out "$work/db.esl"
rm -f ubootefi.var
python3 tools/efivar.py set -i ubootefi.var -n PK  -g "$EFI_GLOBAL_VARIABLE_GUID"          -a nv,bs,rt,at -t file -d "$work/PK.esl"
python3 tools/efivar.py set -i ubootefi.var -n KEK -g "$EFI_GLOBAL_VARIABLE_GUID"          -a nv,bs,rt,at -t file -d "$work/KEK.esl"
python3 tools/efivar.py set -i ubootefi.var -n db  -g "$EFI_IMAGE_SECURITY_DATABASE_GUID" -a nv,bs,rt,at -t file -d "$work/db.esl"
python3 tools/efivar.py print -i ubootefi.var

# require_config FILE FRAGMENT: every "CONFIG_X=y" / "CONFIG_X=..." line of the
# fragment must survive olddefconfig; a silently dropped option (unmet
# dependency) is a build failure, not a warning.
require_config() {
    local config="$1" fragment="$2" line on
    while IFS= read -r line; do
        case "$line" in
            ''|'#'*) continue ;;
        esac
        grep -qxF "$line" "$config" || { echo "$fragment: $line was dropped by Kconfig (unmet dependency?)" >&2; exit 3; }
    done < "$fragment"
    # and every "# CONFIG_X is not set" line must not have come back as =y
    # (a fragment turning an option off that the defconfig selects).
    # (grep exits 1 when a fragment has no such line; under set -e that
    # must not end the build.)
    local off
    off=$(grep -E '^# CONFIG_[A-Z0-9_]+ is not set$' "$fragment" || true)
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        on="${line#\# }"; on="${on% is not set}=y"
        # (`grep && {...}` as the loop's last command would make the
        # function return 1 when the option is correctly off, and set -e
        # would end the build there, silently.)
        if grep -qxF "$on" "$config"; then
            echo "$fragment: ${on%=y} is still enabled (selected by something else?)" >&2
            exit 3
        fi
    done <<< "$off"
}

boards_json=""
for board in $BOARDS; do
    echo "=== building $board"
    obj="$work/out-$board"
    make -s O="$obj" "${board}_defconfig"
    # efi_var_seed.S incbins CONFIG_EFI_VAR_SEED_FILE relative to the assembler's
    # working directory (the O= build tree) while the Makefile dependency names
    # $(srctree)/<file>; an out-of-tree build therefore needs the seed in both.
    cp ubootefi.var "$obj/ubootefi.var"
    ./scripts/kconfig/merge_config.sh -m -O "$obj" "$obj/.config" "$CFG/common-efi.config" "$CFG/${board}-tpm.config" >/dev/null
    make -s O="$obj" olddefconfig
    require_config "$obj/.config" "$CFG/common-efi.config"
    require_config "$obj/.config" "$CFG/${board}-tpm.config"
    make -s O="$obj" -j"$(nproc)" u-boot.bin
    dest="$OUT/$board"
    rm -rf "$dest"; mkdir -p "$dest"
    cp "$obj/u-boot.bin" "$dest/u-boot.bin"
    cp "$obj/.config" "$dest/u-boot.config"
    if [ "$board" = "rpi_arm64" ]; then
        mkdir -p "$dest/overlays"
        dtc -@ -I dts -O dtb -o "$dest/overlays/tpm-soft-spi.dtbo" "$CFG/tpm-soft-spi.dts"
    fi
    (cd "$dest" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
    boards_json="${boards_json:+$boards_json, }\"$board\""
    echo "=== $board: $(stat -c %s "$dest/u-boot.bin") bytes"
done

cat > "$OUT/manifest.json" <<JSON
{
  "uboot_version": "$UBOOT_VERSION",
  "tarball_sha256": "$UBOOT_SHA256",
  "cache_key": "$UBOOT_CACHE_KEY",
  "owner_guid": "$UBOOT_OWNER_GUID",
  "boards": [$boards_json],
  "measured_pcrs": [0, 1, 2, 4, 5, 7],
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
echo "done: $OUT/manifest.json"
