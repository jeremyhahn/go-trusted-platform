#!/bin/bash

# Function to extract ISOs if they aren't already extracted
extract_iso() {
    ISO_FILE=$1
    EXTRACT_DIR="/var/www/html/isos/$(basename "$ISO_FILE" .iso)"
    TFTP_EXTRACT_DIR="/srv/tftp/$(basename "$ISO_FILE" .iso)"
    
    # Check if directory already exists, and extract only if not
    if [ ! -d "$EXTRACT_DIR" ]; then
        echo "Extracting HTTP $ISO_FILE..."
        mkdir -p "$EXTRACT_DIR"
        7z x "$ISO_FILE" -o"$EXTRACT_DIR" -y
        if [ $? -ne 0 ]; then
            echo "Failed to extract $ISO_FILE to HTTP directory"
            exit 1
        fi
    fi

    # Extract to TFTP directory
    if [ ! -d "$TFTP_EXTRACT_DIR" ]; then
        echo "Extracting TFTP $ISO_FILE..."
        mkdir -p "$TFTP_EXTRACT_DIR"
        7z x "$ISO_FILE" -o"$TFTP_EXTRACT_DIR" -y
        if [ $? -ne 0 ]; then
            echo "Failed to extract $ISO_FILE to TFTP directory"
            exit 1
        fi
    fi
}

configure_pxe_boot() {
    PXE_MENU_PATH="/srv/tftp/pxelinux.cfg/default"
    echo "Creating PXE menu..."

    # Get the local IP address dynamically
    LOCAL_IP=$(hostname -I | awk '{print $1}')

    # List all directories in /var/www/html/isos
    # for DIR in /var/www/html/isos/*/; do
    #     ISO_NAME=$(basename "$DIR")
    #     echo "LABEL $ISO_NAME" >> "$PXE_MENU_PATH"
    #     echo "    MENU LABEL Install $ISO_NAME" >> "$PXE_MENU_PATH"
    #     echo "    KERNEL /$ISO_NAME/install.amd/vmlinuz" >> "$PXE_MENU_PATH"
    #     echo "    INITRD /$ISO_NAME/install.amd/initrd.gz" >> "$PXE_MENU_PATH"
    #     echo "    APPEND boot=net url=http://192.168.50.100/isos/$ISO_NAME" >> "$PXE_MENU_PATH"
    # done

    # Minimal PXE configuration
    echo "DEFAULT menu.c32" > "$PXE_MENU_PATH"
    echo "PROMPT 0" >> "$PXE_MENU_PATH"
    echo "MENU TITLE PXE Boot Menu" >> "$PXE_MENU_PATH"
    echo "TIMEOUT 100" >> "$PXE_MENU_PATH"

    # Configure the entry for Debian 12 (BIOS)
    echo "LABEL Debian 12 (BIOS)" >> "$PXE_MENU_PATH"
    echo "    MENU LABEL Debian 12 (BIOS)" >> "$PXE_MENU_PATH"
    echo "    KERNEL /debian-12/debian-installer/amd64/linux" >> "$PXE_MENU_PATH"
    echo "    APPEND auto=true priority=critical vga=788 initrd=debian-12/debian-installer/amd64/initrd.gz boot=net preseed/url=http://$LOCAL_IP/isos/debian-12/preseed.cfg" >> "$PXE_MENU_PATH"
    # #echo "    APPEND auto=true priority=critical vga=788 initrd=debian-12/debian-installer/amd64/initrd.gz boot=net url=http://192.168.50.100/isos/debian-12 preseed/url=http://192.168.50.100/isos/debian-12/preseed.cfg" >> "$PXE_MENU_PATH"
    # echo "    INITRD /debian-12/debian-installer/amd64/initrd.gz" >> "$PXE_MENU_PATH"
    # echo "    APPEND boot=net url=http://192.168.50.100/isos/debian-12" >> "$PXE_MENU_PATH"

    # Raspberry Pi ARM entry
    echo "LABEL Raspberry Pi (ARM)" >> "$PXE_MENU_PATH"
    echo "    MENU LABEL Raspberry Pi (ARM)" >> "$PXE_MENU_PATH"
    echo "    KERNEL /rpios64-lite/kernel8.img" >> "$PXE_MENU_PATH"
    echo "    INITRD /rpios64-lite/initrd.img" >> "$PXE_MENU_PATH"
    echo "    APPEND root=/dev/mmcblk0p2 rw ip=dhcp rootwait" >> "$PXE_MENU_PATH"

    # VyOS entry
    echo "LABEL VyOS 1.5 (BIOS)" >> "$PXE_MENU_PATH"
    echo "    MENU LABEL VyOS 1.5 (BIOS)" >> "$PXE_MENU_PATH"
    echo "    KERNEL /vyos-1.5/live/vmlinuz" >> "$PXE_MENU_PATH"
    echo "    INITRD /vyos-1.5/live/initrd.img boot=live nopersistence noautologin fetch=http://$LOCAL_IP/isos/vyos-1.5/live/filesystem.squashfs" >> "$PXE_MENU_PATH"
}

# Ensure the necessary directories are set up
mkdir -p /srv/tftp/pxelinux.cfg /var/www/html/isos

cp -R /var/www/html/isos/debian-12 /srv/tftp/debian-12
chown tftp:tftp /srv/tftp/debian-12

cp -R /var/www/html/isos/vyos-1.5 /srv/tftp/vyos-1.5
chown tftp:tftp /srv/tftp/vyos-1.5

cp -R /var/www/html/isos/rpios64-lite /srv/tftp/rpios64-lite
chown tftp:tftp /srv/tftp/rpios64-lite

# echo "Unpacking netboot.tar.gz..."
# tar -xzf /var/www/html/isos/netboot.tar.gz -C /srv/tftp

# # Prepare Syslinux files and PXE menu
# echo "Starting to extract and configure ISOs..."
# for ISO_FILE in /var/www/html/isos/*.iso; do
#     extract_iso "$ISO_FILE"
# done

configure_pxe_boot

chown -R tftp:tftp /srv/tftp/

# Start necessary services
echo "Starting Apache2..."
/usr/sbin/apache2ctl -D FOREGROUND &

echo "Starting ISC DHCP Server..."
/usr/sbin/isc-dhcp-server &

echo "Starting TFTP server..."
/etc/init.d/tftpd-hpa start

# Wait for services to finish
wait



# Function to configure PXE boot with minimal vmlinuz and initrd from Syslinux
configure_pxe_boot() {
    PXE_MENU_PATH="/srv/tftp/pxelinux.cfg/default"
    echo "Creating PXE menu..."

    # Get the local IP address dynamically
    LOCAL_IP=$(hostname -I | awk '{print $1}')

    # Minimal PXE configuration
    echo "DEFAULT menu.c32" > "$PXE_MENU_PATH"
    echo "PROMPT 0" >> "$PXE_MENU_PATH"
    echo "MENU TITLE PXE Boot Menu" >> "$PXE_MENU_PATH"
    echo "TIMEOUT 100" >> "$PXE_MENU_PATH"

    # Configure the entry for Debian 12 (BIOS)
    echo "LABEL Debian 12 (BIOS)" >> "$PXE_MENU_PATH"
    echo "    MENU LABEL Debian 12 (BIOS)" >> "$PXE_MENU_PATH"
    echo "    KERNEL /debian-12/debian-installer/amd64/linux" >> "$PXE_MENU_PATH"
    echo "    APPEND auto=true priority=critical vga=788 initrd=debian-12/debian-installer/amd64/initrd.gz boot=net preseed/url=http://$LOCAL_IP/isos/debian-12/preseed.cfg" >> "$PXE_MENU_PATH"

    # Raspberry Pi ARM entry
    echo "LABEL Raspberry Pi (ARM)" >> "$PXE_MENU_PATH"
    echo "    MENU LABEL Raspberry Pi (ARM)" >> "$PXE_MENU_PATH"
    echo "    KERNEL /rpios64-lite/kernel8.img" >> "$PXE_MENU_PATH"
    echo "    INITRD /rpios64-lite/initrd.img" >> "$PXE_MENU_PATH"
    echo "    APPEND root=/dev/mmcblk0p2 rw ip=dhcp rootwait" >> "$PXE_MENU_PATH"

    # VyOS entry
    echo "LABEL VyOS 1.5 (BIOS)" >> "$PXE_MENU_PATH"
    echo "    MENU LABEL VyOS 1.5 (BIOS)" >> "$PXE_MENU_PATH"
    echo "    KERNEL /vyos-1.5/live/vmlinuz" >> "$PXE_MENU_PATH"
    echo "    INITRD /vyos-1.5/live/initrd.img boot=live nopersistence noautologin fetch=http://$LOCAL_IP/isos/vyos-1.5/live/filesystem.squashfs" >> "$PXE_MENU_PATH"
}

# Ensure the necessary directories are set up
mkdir -p /srv/tftp/pxelinux.cfg /var/www/html/isos

cp -R /var/www/html/isos/debian-12 /srv/tftp/debian-12
chown tftp:tftp /srv/tftp/debian-12

cp -R /var/www/html/isos/vyos-1.5 /srv/tftp/vyos-1.5
chown tftp:tftp /srv/tftp/vyos-1.5

cp -R /var/www/html/isos/rpios64-lite /srv/tftp/rpios64-lite
chown tftp:tftp /srv/tftp/rpios64-lite

# Configure PXE Boot
configure_pxe_boot

# Set permissions for TFTP directory
chown -R tftp:tftp /srv/tftp/

# Start necessary services
echo "Starting Apache2..."
/usr/sbin/apache2ctl -D FOREGROUND &

echo "Starting ISC DHCP Server..."
/usr/sbin/isc-dhcp-server &

echo "Starting TFTP server..."
/etc/init.d/tftpd-hpa start

# Wait for services to finish
wait
