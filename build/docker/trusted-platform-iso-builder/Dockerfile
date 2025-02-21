ARG BASE_IMAGE=debian:bookworm

FROM $BASE_IMAGE

ARG ISO_NAME=trusted-platform
ARG UEFI_GRUB_DEFAULT=0
ARG DEBIAN_VERSION=12.9.0

ENV DEBIAN_FRONTEND=noninteractive
ENV ISO_NAME=${ISO_NAME}

RUN rm -rf /etc/apt/sources.list.d/* && \
    echo "deb [arch=amd64] http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    echo "deb [arch=amd64] http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware" >> /etc/apt/sources.list && \
    echo "deb [arch=amd64] http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware" >> /etc/apt/sources.list && \
    apt-get update && apt-get install -y \
    xorriso \
    isolinux \
    syslinux-common \
    genisoimage \
    wget \
    p7zip-full \
    rsync \
    ca-certificates \
    sbsigntool \
    efibootmgr \
    efitools \
    efivar \
    grub-efi-amd64-bin \
    uuid-runtime \
    dosfstools \
    mtools \
    cpio \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Download and extract the Debian netinst ISO
RUN wget https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/SHA256SUMS -O SHA256SUMS && \
    wget https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-${DEBIAN_VERSION}-amd64-netinst.iso -O debian-${DEBIAN_VERSION}-amd64-netinst.iso && \
    grep debian-${DEBIAN_VERSION}-amd64-netinst.iso SHA256SUMS | sha256sum -c -

RUN mkdir -p debian_iso && \
    xorriso -osirrox on \
      -indev debian-${DEBIAN_VERSION}-amd64-netinst.iso \
      -extract / debian_iso && \
    chmod -R u+w debian_iso

# Copy custom secure boot keys and preseed configurations
COPY secure-boot-keys debian_iso/secure-boot-keys
COPY preseed.cfg debian_iso/preseed.cfg
COPY preseed-swtpm.cfg debian_iso/preseed-swtpm.cfg
COPY playbook.yaml debian_iso/playbook.yaml
COPY late_command.sh debian_iso/late_command.sh
COPY ansible debian_iso/ansible

RUN chmod +x debian_iso/late_command.sh

# Generate and sign GRUB EFI binary
RUN grub-mkimage -o debian_iso/boot/grub/x86_64-efi/grubx64.efi \
    -O x86_64-efi \
    -p /boot/grub \
    part_gpt fat ext2 normal linux boot configfile && \
    sbsign --key debian_iso/secure-boot-keys/DB.key \
           --cert debian_iso/secure-boot-keys/DB.crt \
           --output debian_iso/boot/grub/x86_64-efi/grubx64.efi \
           debian_iso/boot/grub/x86_64-efi/grubx64.efi && \
    cp debian_iso/boot/grub/x86_64-efi/grubx64.efi debian_iso/EFI/boot/grubx64.efi

# Sign the kernel if not already signed
RUN if ! sbverify --cert debian_iso/secure-boot-keys/DB.crt debian_iso/install.amd/vmlinuz; then \
        sbsign --key debian_iso/secure-boot-keys/DB.key \
               --cert debian_iso/secure-boot-keys/DB.crt \
               --output debian_iso/install.amd/vmlinuz.signed \
               debian_iso/install.amd/vmlinuz; \
    else \
        cp debian_iso/install.amd/vmlinuz debian_iso/install.amd/vmlinuz.signed; \
    fi

# Sign EFI binaries inside efi.img
RUN mkdir -p /build/efi_img && \
    7z x debian_iso/boot/grub/efi.img -o/build/efi_img && \
    sbsign --key debian_iso/secure-boot-keys/DB.key \
           --cert debian_iso/secure-boot-keys/DB.crt \
           --output /build/efi_img/efi/boot/bootx64.efi \
           /build/efi_img/efi/boot/bootx64.efi && \
    sbsign --key debian_iso/secure-boot-keys/DB.key \
           --cert debian_iso/secure-boot-keys/DB.crt \
           --output /build/efi_img/efi/boot/grubx64.efi \
           /build/efi_img/efi/boot/grubx64.efi && \
    mkfs.vfat -n "EFIBOOT" -C /build/efi_tmp.img 16384 && \
    mcopy -s -i /build/efi_tmp.img /build/efi_img/* :: && \
    mv /build/efi_tmp.img debian_iso/boot/grub/efi.img && \
    rm -rf /build/efi_img

# Create EFI GRUB menu using the build argument for the default menu item
RUN mv debian_iso/boot/grub/grub.cfg debian_iso/boot/grub/grub.cfg.bak && \
    cat <<EOF > debian_iso/boot/grub/grub.cfg
set default=${UEFI_GRUB_DEFAULT}
set timeout=5

menuentry "Trusted Platform Install (HW TPM 2.0)" {
    linux /install.amd/vmlinuz.signed auto=true priority=critical preseed/file=/cdrom/preseed.cfg
    initrd /install.amd/initrd.gz
}

menuentry "Trusted Platform Install (SW TPM 2.0)" {
    linux /install.amd/vmlinuz auto=true priority=critical preseed/file=/cdrom/preseed-swtpm.cfg
    initrd /install.amd/initrd.gz
}

EOF

RUN cat debian_iso/boot/grub/grub.cfg.bak >> debian_iso/boot/grub/grub.cfg

# Create the final ISO with signed components, using the ISO_NAME argument for the file name
RUN xorriso -as mkisofs \
    -o ${ISO_NAME}.iso \
    -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin \
    -c isolinux/boot.cat \
    -b isolinux/isolinux.bin \
       -no-emul-boot \
       -boot-load-size 4 \
       -boot-info-table \
    -eltorito-alt-boot \
    -e boot/grub/efi.img \
       -no-emul-boot \
       -isohybrid-gpt-basdat \
    -r -J -joliet-long \
    debian_iso

# Copy the final ISO to the /iso directory using the ISO_NAME argument
# CMD ["cp", "/build/${ISO_NAME}.iso", "/iso/${ISO_NAME}.iso"]

CMD cp /build/${ISO_NAME}.iso /iso/${ISO_NAME}.iso
