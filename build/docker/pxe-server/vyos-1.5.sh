#!/bin/bash

set -e 

MIRROR="github.com"
ISO_NAME="vyos-1.5-rolling-202412100007-generic-amd64"
ISO_URL="https://github.com/vyos/vyos-nightly-build/releases/download/1.5-rolling-202412140007/vyos-1.5-rolling-202412140007-generic-amd64.iso"
ISODIR="volume/iso/vyos-1.5"

mkdir -p "$ISODIR"

echo "Downloading VyOS ISO..."
wget "$ISO_URL" -O "$ISODIR/$ISO_NAME.iso"

echo "Extracting VyOS ISO..."
7z x "$ISODIR/$ISO_NAME.iso" -o"$ISODIR" -y

find "$ISODIR" -type f -exec sed -i 's|live\/vmlinuz|vyos-1.5\/live\/vmlinuz|g' {} +
find "$ISODIR" -type f -exec sed -i 's|live\/initrd.img|vyos-1.5\/live\/initrd.img|g' {} +

echo "VyOS 1.5 has been downloaded, extracted and prepared for PXE boot."
