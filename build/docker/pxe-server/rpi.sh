#!/bin/bash

set -e  # Exit immediately if a command fails

# Set variables
RPI_IMAGE_URL="https://downloads.raspberrypi.com/raspios_lite_arm64/images/raspios_lite_arm64-2024-11-19/2024-11-19-raspios-bookworm-arm64-lite.img.xz"
ISODIR="./volume/iso/rpios64-lite"
IMAGE_FILE="2024-11-19-raspios-bookworm-arm64-lite.img.xz"
IMG_FILE="${ISODIR}/2024-11-19-raspios-bookworm-arm64-lite.img"
LOOP_DEVICE=""
BOOT_PARTITION="/mnt/rpi-os/boot"
ROOT_PARTITION="/mnt/rpi-os"

# Create the directories if they don't exist
mkdir -p "$ISODIR"

# Download the Raspberry Pi OS image file (only if it doesn't already exist)
if [ ! -f "$ISODIR/$IMAGE_FILE" ]; then
    echo "Downloading Raspberry Pi OS image..."
    wget -O "$ISODIR/$IMAGE_FILE" "$RPI_IMAGE_URL" || { echo "Download failed!"; exit 1; }
else
    echo "Image file already exists, skipping download."
fi

# Extract the .xz file (only if it doesn't already exist)
if [ ! -f "$IMG_FILE" ]; then
    echo "Extracting Raspberry Pi OS image..."
    xz -d "$ISODIR/$IMAGE_FILE" || { echo "Extraction failed!"; exit 1; }
else
    echo "Image file already extracted, skipping extraction."
fi

# Check if the .img file exists after extraction
if [ ! -f "$IMG_FILE" ]; then
    echo "Image file extraction failed! Exiting."
    exit 1
fi

# Detach all loop devices to ensure no conflict
echo "Detaching all loop devices..."
sudo losetup -D

# Try to find an available loop device by incrementing the loop device number
for i in {0..15}; do
    LOOP_DEVICE="/dev/loop$i"
    if ! sudo losetup "$LOOP_DEVICE" &>/dev/null; then
        break
    fi
done

# If no free loop device found, abort with an error
if [ -z "$LOOP_DEVICE" ]; then
    echo "No available loop device found! Exiting."
    exit 1
fi

echo "Loop device created at $LOOP_DEVICE"

# Set up the partitions using losetup
echo "Setting up partitions on loop device..."
sudo losetup -P "$LOOP_DEVICE" "$IMG_FILE" || { echo "Failed to set up partitions on loop device!"; exit 1; }

# Create the mount points
sudo mkdir -p /mnt/rpi-os
sudo mkdir -p "$BOOT_PARTITION"

# List the partitions to verify the setup
echo "Listing partitions on loop device..."
sudo lsblk "$LOOP_DEVICE"

# Mount the root and boot partitions
echo "Mounting the root partition..."
sudo mount "${LOOP_DEVICE}p2" "$ROOT_PARTITION" || { echo "Failed to mount root partition!"; exit 1; }

echo "Mounting the boot partition..."
sudo mount "${LOOP_DEVICE}p1" "$BOOT_PARTITION" || { echo "Failed to mount boot partition!"; exit 1; }

# Verify the contents of the boot partition
echo "Contents of boot partition:"
sudo ls "$BOOT_PARTITION"

# Copy the necessary files for PXE boot
echo "Copying files for PXE boot..."
sudo cp -R "$BOOT_PARTITION/"* "$ISODIR/"  # Corrected path for copying files

# Clean up the loop device
sudo losetup -d "$LOOP_DEVICE" || { echo "Failed to detach loop device!"; exit 1; }

# Unmount the partitions
echo "Unmounting the Raspberry Pi image..."
sudo umount "$BOOT_PARTITION" || { echo "Failed to unmount boot partition!"; exit 1; }
sudo umount "$ROOT_PARTITION" || { echo "Failed to unmount root partition!"; exit 1; }

# Check if the mount points are still in use before removing them
if mountpoint -q "$BOOT_PARTITION"; then
    echo "Warning: Boot partition still mounted!"
else
    sudo rmdir "$BOOT_PARTITION"
fi

if mountpoint -q "$ROOT_PARTITION"; then
    echo "Warning: Root partition still mounted!"
else
    sudo rmdir "$ROOT_PARTITION"
fi

echo "Raspberry Pi OS image has been extracted and prepared for PXE boot."
