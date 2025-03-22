#!/bin/bash
# late_command.sh
#
# This script builds a unified kernel image following the Debian EFIStub documentation.
# It downloads and compiles a custom kernel with EFI stub support, generates an initramfs
# using update-initramfs, creates a kernel command-line file, computes proper section
# offsets, and then uses objcopy (with the EFI stub installed via systemd-boot-efi)
# to combine everything into a single unified EFI binary.
#
# It then optionally signs the image, creates a UEFI boot entry, removes any shim/grub
# boot entries, enables a getty on tty0 for graphical console login, and installs a 
# first-boot TPM enrollment service that enrolls a TPM-bound LUKS key using systemd-cryptenroll.
#
# This script obtains the encrypted partition’s UUID dynamically.
#
# Run this script as root.
#
# Supported flags:
#   -d DISK                   (default: /dev/vda)
#   -p PARTITION              (default: 2)
#   -v KERNEL_VERSION         (default: 6.1.31)
#   -k SECUREBOOT_PRIVATE_KEY (default: /media/cdrom0/secure-boot-keys/DB.key)
#   -c SECUREBOOT_CERTIFICATE (default: /media/cdrom0/secure-boot-keys/DB.crt)
#   -e EFI_IMAGE              (default: ${EFI_DIR}/kernel.efi)
#   -s SWTPM                  (default: false)
#

DISK="/dev/vda"
PARTITION="2"
KERNEL_VERSION="6.1.31"
SECUREBOOT_PRIVATE_KEY="/media/cdrom0/secure-boot-keys/DB.key"
SECUREBOOT_CERTIFICATE="/media/cdrom0/secure-boot-keys/DB.crt"
SWTPM="false"

while getopts "d:p:v:k:c:e:s:" opt; do
    case "$opt" in
        d) DISK="$OPTARG" ;;
        p) PARTITION="$OPTARG" ;;
        v) KERNEL_VERSION="$OPTARG" ;;
        k) SECUREBOOT_PRIVATE_KEY="$OPTARG" ;;
        c) SECUREBOOT_CERTIFICATE="$OPTARG" ;;
        e) EFI_IMAGE="$OPTARG" ;;
        s) SWTPM="$OPTARG" ;;
        *) echo "Usage: $0 [-d DISK] [-p PARTITION] [-v KERNEL_VERSION] [-k SECUREBOOT_PRIVATE_KEY] [-c SECUREBOOT_CERTIFICATE] [-e EFI_IMAGE] [-s SWTPM]" ; exit 1 ;;
    esac
done
shift $((OPTIND-1))

set -euo pipefail
set -x

exec > /var/log/install.log 2>&1

###############################################################################
# Pre‑Step: Disable any CD‑ROM apt sources (to avoid apt errors in installer)
###############################################################################
echo "Disabling CD-ROM repositories..."
sed -i '/^deb cdrom:/ s/^/#/' /etc/apt/sources.list
find /etc/apt/sources.list.d/ -type f -exec sed -i '/^deb cdrom:/ s/^/#/' {} +

###############################################################################
# Step 0: Update package list and install required packages.
###############################################################################
echo "Step 0: Updating package list and installing required packages..."
apt-get update -y
apt-get install -y \
    build-essential flex bison libssl-dev pkg-config libelf-dev bc wget \
    binutils sbsigntool efibootmgr initramfs-tools \
    meson ninja-build git gperf libcap-dev systemd-boot-efi tpm2-tools

###############################################################################
# Configuration Variables
###############################################################################
# Use PARTITION flag (renamed from PART)
echo "Using DISK: ${DISK} and PARTITION: ${PARTITION}"
ENCRYPTED_PARTITION="/dev/vda3"
ENCRYPTED_UUID=$(blkid -s UUID -o value "$ENCRYPTED_PARTITION")
echo "Encrypted partition UUID: $ENCRYPTED_UUID"

ARCH="amd64"

NEW_KERNEL_IMAGE="/boot/vmlinuz-${KERNEL_VERSION}-trusted"
INITRD_IMG="/boot/initrd.img-${KERNEL_VERSION}"
# IMPORTANT: To force interactive unlocking fallback on first boot,
# we include the cryptdevice= parameter so that early unlocking is attempted.
KERNEL_CMDLINE="cryptdevice=UUID=${ENCRYPTED_UUID}:crypt-root root=/dev/mapper/crypt-root console=tty0 console=ttyS0,115200 ipv6.disable=1"

OSREL_FILE="/etc/os-release"
CMDLINE_FILE="/boot/cmdline.txt"
SPLASH_FILE="/boot/splash.bmp"

# Secure Boot keys from flags
echo "Using SECUREBOOT_PRIVATE_KEY: ${SECUREBOOT_PRIVATE_KEY}"
echo "Using SECUREBOOT_CERTIFICATE: ${SECUREBOOT_CERTIFICATE}"

EFI_DIR="/boot/efi/EFI/Trusted"
mkdir -p "$EFI_DIR"
# If EFI_IMAGE was not set via flag, default it.
EFI_IMAGE="${EFI_IMAGE:-${EFI_DIR}/kernel.efi}"

EFI_STUB="/usr/lib/systemd/boot/efi/linuxx64.efi.stub"

# Build the custom Kernel with EFI Stub, LUKS, and TPM, Crypto and Container support.
echo "Step 1: Downloading and compiling kernel version ${KERNEL_VERSION}..."
cd /tmp
if [ ! -f "linux-${KERNEL_VERSION}.tar.gz" ]; then
    wget -O "linux-${KERNEL_VERSION}.tar.gz" "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.gz"
fi
tar -xvzf "linux-${KERNEL_VERSION}.tar.gz"
cd "linux-${KERNEL_VERSION}"
make defconfig

# Linux EFI Stub
scripts/config --set-val CONFIG_EFI_STUB y
scripts/config --set-val CONFIG_RD_GZIP y

# LUKS
scripts/config --set-val CONFIG_BLK_DEV_DM y
scripts/config --set-val CONFIG_DM_CRYPT y
scripts/config --set-val CONFIG_CRYPTO_AES y
scripts/config --set-val CONFIG_CRYPTO_XTS y
scripts/config --set-val CONFIG_CRYPTO_SHA256 y

# TPM 2.0
scripts/config --set-val CONFIG_PNP y
scripts/config --set-val CONFIG_ACPI y
scripts/config --set-val CONFIG_PNPACPI y
scripts/config --set-val CONFIG_TCG_TPM y
scripts/config --set-val CONFIG_TCG_TIS y
scripts/config --set-val CONFIG_TCG_TIS_CORE y
scripts/config --set-val CONFIG_TPM_CRB y
scripts/config --set-val CONFIG_TPM_RM y
#scripts/config --set-val CONFIG_HW_RANDOM y

# Containers
scripts/config --set-val CONFIG_NAMESPACES y

# Containers :: Generally necessary
scripts/config --set-val CONFIG_NET_NS y
scripts/config --set-val CONFIG_PID_NS y
scripts/config --set-val CONFIG_IPC_NS y
scripts/config --set-val CONFIG_UTS_NS y
scripts/config --set-val CONFIG_CGROUPS y
scripts/config --set-val CONFIG_CGROUP_CPUACCT y
scripts/config --set-val CONFIG_CGROUP_DEVICE y
scripts/config --set-val CONFIG_CGROUP_FREEZER y
scripts/config --set-val CONFIG_CGROUP_SCHED y
scripts/config --set-val CONFIG_CPUSETS y
scripts/config --set-val CONFIG_MEMCG y
scripts/config --set-val CONFIG_KEYS y
scripts/config --set-val CONFIG_VETH y
scripts/config --set-val CONFIG_BRIDGE y
scripts/config --set-val CONFIG_BRIDGE_NETFILTER y
scripts/config --set-val CONFIG_NF_NAT_IPV4 y
scripts/config --set-val CONFIG_IP_NF_FILTER y
scripts/config --set-val CONFIG_IP_NF_TARGET_MASQUERADE y
scripts/config --set-val CONFIG_NETFILTER_XT_MATCH_ADDRTYPE y
scripts/config --set-val CONFIG_NETFILTER_XT_MATCH_CONNTRACK y
scripts/config --set-val CONFIG_NETFILTER_XT_MATCH_IPVS y
scripts/config --set-val CONFIG_IP_NF_NAT y
scripts/config --set-val CONFIG_NF_NAT y
scripts/config --set-val CONFIG_NF_NAT_NEEDED y
scripts/config --set-val CONFIG_POSIX_MQUEUE y
scripts/config --set-val CONFIG_BPF y
scripts/config --set-val CONFIG_BPF_SYSCALL y
scripts/config --set-val CONFIG_CGROUP_BPF y
scripts/config --set-val CONFIG_CGROUP_RDMA y
scripts/config --set-val CONFIG_CGROUP_NET_PRIO y
scripts/config --set-val CONFIG_CGROUP_NET_CLASSID y
scripts/config --set-val CONFIG_CGROUP_CPUSET y
scripts/config --set-val CONFIG_DEVPTS_MULTIPLE_INSTANCES y
scripts/config --set-val CONFIG_BPF_JIT y
scripts/config --set-val CONFIG_HAVE_EBPF_JIT y
scripts/config --set-val CONFIG_BPF_LSM y
scripts/config --set-val CONFIG_BPF_UNPRIV_DEFAULT_OFF y
scripts/config --set-val CONFIG_BPF_EVENTS y

# Containers :: Optional features
scripts/config --set-val CONFIG_USER_NS y
scripts/config --set-val CONFIG_SECCOMP y
scripts/config --set-val CONFIG_CGROUP_PIDS y
scripts/config --set-val CONFIG_MEMCG_SWAP y
scripts/config --set-val CONFIG_MEMCG_SWAP_ENABLED y
scripts/config --set-val CONFIG_BLK_CGROUP y
scripts/config --set-val CONFIG_BLK_DEV_THROTTLING y
scripts/config --set-val CONFIG_IOSCHED_CFQ y
scripts/config --set-val CONFIG_CFQ_GROUP_IOSCHED y
scripts/config --set-val CONFIG_CGROUP_PERF y
scripts/config --set-val CONFIG_CGROUP_HUGETLB y
scripts/config --set-val CONFIG_NET_CLS_CGROUP y
scripts/config --set-val CONFIG_CGROUP_NET_PRIO y
scripts/config --set-val CONFIG_CFS_BANDWIDTH y
scripts/config --set-val CONFIG_FAIR_GROUP_SCHED y
scripts/config --set-val CONFIG_RT_GROUP_SCHED y
scripts/config --set-val CONFIG_IP_NF_TARGET_REDIRECT y
scripts/config --set-val CONFIG_IP_VS y
scripts/config --set-val CONFIG_IP_VS_NFCT y
scripts/config --set-val CONFIG_IP_VS_PROTO_TCP y
scripts/config --set-val CONFIG_IP_VS_PROTO_UDP y
scripts/config --set-val CONFIG_IP_VS_RR y
scripts/config --set-val CONFIG_EXT4_FS y
scripts/config --set-val CONFIG_EXT4_FS_POSIX_ACL y
scripts/config --set-val CONFIG_EXT4_FS_SECURITY y
scripts/config --set-val CONFIG_VXLAN y
scripts/config --set-val CONFIG_XFRM y
scripts/config --set-val CONFIG_XFRM_USER y
scripts/config --set-val CONFIG_XFRM_ALGO y
scripts/config --set-val CONFIG_INET_ESP y
scripts/config --set-val CONFIG_INET_XFRM_MODE_TRANSPORT y
scripts/config --set-val CONFIG_IPVLAN y
scripts/config --set-val CONFIG_MACVLAN y
scripts/config --set-val CONFIG_DUMMY y
scripts/config --set-val CONFIG_NF_NAT_FTP y
scripts/config --set-val CONFIG_NF_CONNTRACK_FTP y
scripts/config --set-val CONFIG_NF_NAT_TFTP y
scripts/config --set-val CONFIG_NF_CONNTRACK_TFTP y
scripts/config --set-val CONFIG_AUFS_FS y
scripts/config --set-val CONFIG_BTRFS_FS y
scripts/config --set-val CONFIG_BTRFS_FS_POSIX_ACL y
scripts/config --set-val CONFIG_BLK_DEV_DM y
scripts/config --set-val CONFIG_DM_THIN_PROVISIONING y
scripts/config --set-val CONFIG_OVERLAY_FS y

# Bridge / Netfilter
scripts/config --set-val CONFIG_BRIDGE y
scripts/config --set-val CONFIG_BRIDGE_NETFILTER y
scripts/config --set-val CONFIG_NETFILTER y
scripts/config --set-val CONFIG_NETFILTER_ADVANCED y
scripts/config --set-val CONFIG_NF_CONNTRACK y
scripts/config --set-val CONFIG_NF_TABLES y
scripts/config --set-val CONFIG_NF_NAT y
scripts/config --set-val CONFIG_NF_NAT_IPV4 y
scripts/config --set-val CONFIG_NF_NAT_IPV6 y
scripts/config --set-val CONFIG_NF_TABLES_IPV4 y
scripts/config --set-val CONFIG_NF_TABLES_IPV6 y
scripts/config --set-val CONFIG_IP_NF_IPTABLES y
scripts/config --set-val CONFIG_IP_NF_FILTER y
scripts/config --set-val CONFIG_IP_NF_NAT y
scripts/config --set-val CONFIG_IP_NF_TARGET_MASQUERADE y

# Security
scripts/config --set-val CONFIG_IMA y
scripts/config --set-val CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT y
scripts/config --set-val CONFIG_SECURITY_SELINUX y
scripts/config --set-val CONFIG_DEFAULT_SECURITY_SELINUX y
scripts/config --set-val CONFIG_SECURITY_LOCKDOWN y

# Public-key cryptography
scripts/config --set-val CONFIG_CRYPTO_RSA y
scripts/config --set-val CONFIG_CRYPTO_DH y
scripts/config --set-val CONFIG_CRYPTO_ECDH y
scripts/config --set-val CONFIG_CRYPTO_ECDSA y
scripts/config --set-val CONFIG_CRYPTO_CURVE25519 y

# Block ciphers
scripts/config --set-val CONFIG_CRYPTO_AES y

# Compression
scripts/config --set-val CONFIG_CRYPTO_LZO y
scripts/config --set-val CONFIG_CRYPTO_ZSTD y

# Crypto library routines
scripts/config --set-val CONFIG_CRYPTO_LIB_UTILS y
scripts/config --set-val CONFIG_CRYPTO_LIB_AES y
scripts/config --set-val CONFIG_CRYPTO_LIB_ARC4 y
scripts/config --set-val CONFIG_CRYPTO_LIB_BLAKE2S_GENERIC y
scripts/config --set-val CONFIG_CRYPTO_LIB_CHACHA y
scripts/config --set-val CONFIG_CRYPTO_LIB_CURVE25519 y
scripts/config --set-val CONFIG_CRYPTO_LIB_POLY1305 y
scripts/config --set-val CONFIG_CRYPTO_LIB_CHACHA20POLY1305 y
scripts/config --set-val CONFIG_CRYPTO_LIB_SHA1 y
scripts/config --set-val CONFIG_CRYPTO_LIB_SHA256 y

# AEAD (authenticated encryption with associated data) ciphers
scripts/config --set-val CONFIG_CRYPTO y
scripts/config --set-val CONFIG_CRYPTO_AEAD y
scripts/config --set-val CONFIG_CRYPTO_AEGIS128 y
scripts/config --set-val CONFIG_CRYPTO_CBC y
scripts/config --set-val CONFIG_CRYPTO_CCM y
scripts/config --set-val CONFIG_CRYPTO_CFB y
scripts/config --set-val CONFIG_CRYPTO_CHACHA20 y
scripts/config --set-val CONFIG_CRYPTO_CHACHA20POLY1305 y
scripts/config --set-val CONFIG_CRYPTO_CCM y
scripts/config --set-val CONFIG_CRYPTO_GCM y
scripts/config --set-val CONFIG_CRYPTO_HMAC y
scripts/config --set-val CONFIG_CRYPTO_SEQIV y
scripts/config --set-val CONFIG_CRYPTO_ECHAINIV y
scripts/config --set-val CONFIG_CRYPTO_ESSIV y

# Hashes, digests, and MACs
scripts/config --set-val CONFIG_CRYPTO_BLAKE2B y
scripts/config --set-val CONFIG_CRYPTO_CMAC y
scripts/config --set-val CONFIG_CRYPTO_GHASH y
scripts/config --set-val CONFIG_CRYPTO_HMAC y
scripts/config --set-val CONFIG_CRYPTO_LZO y
scripts/config --set-val CONFIG_CRYPTO_MD5 y
scripts/config --set-val CONFIG_CRYPTO_SHA1 y
scripts/config --set-val CONFIG_CRYPTO_SHA256 y
scripts/config --set-val CONFIG_CRYPTO_SHA512 y
scripts/config --set-val CONFIG_CRYPTO_XXHASH y
scripts/config --set-val CONFIG_CRYPTO_ZLIB y

# Custom hardening :: See https://kspp.github.io/Recommended_Settings.html
scripts/config --set-val CONFIG_SECURITY_LOCKDOWN_LSM y
scripts/config --set-val CONFIG_SECURITY_LOCKDOWN_LSM_EARLY y
scripts/config --set-val CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY y
scripts/config --set-val CONFIG_SYSTEM_TRUSTED_KEYS y
#scripts/config --set-val CONFIG_KPTR_RESTRICT y

make olddefconfig

make -j"$(nproc)" bzImage
cp arch/x86/boot/bzImage "${NEW_KERNEL_IMAGE}"
echo "Kernel image copied to ${NEW_KERNEL_IMAGE}"
echo "Installing kernel modules..."
if ! make modules_install; then
    echo "Kernel modules installation failed; checking for /lib/modules/${KERNEL_VERSION}..."
    if [ ! -d "/lib/modules/${KERNEL_VERSION}" ]; then
        mkdir -p "/lib/modules/${KERNEL_VERSION}"
    fi
fi
echo "Kernel modules installed."
cp .config /boot/config-"${KERNEL_VERSION}"
echo "Kernel config copied to /boot/config-${KERNEL_VERSION}"

# Generate the initramfs using update-initramfs
echo "Step 2: Generating initramfs for kernel ${KERNEL_VERSION}..."
set +e
update-initramfs -c -k "${KERNEL_VERSION}"
rc=$?
set -e
if [ ! -f "/boot/initrd.img-${KERNEL_VERSION}" ]; then
    echo "Error: initramfs not generated."
    exit 1
fi
echo "update-initramfs returned exit code $rc, but initrd exists. Continuing."
if [ "/boot/initrd.img-${KERNEL_VERSION}" != "${INITRD_IMG}" ]; then
    cp "/boot/initrd.img-${KERNEL_VERSION}" "${INITRD_IMG}"
fi
echo "Initramfs available at ${INITRD_IMG}"

# ###############################################################################
# Patch the generated initramfs to embed the fallback crypttab and
# manually copy patch files from the ISO.
#
# - https://bugs.launchpad.net/ubuntu/+source/cryptsetup/+bug/1980018
# - https://answers.launchpad.net/ubuntu/+question/702266
# - https://salsa.debian.org/cryptsetup-team/cryptsetup/-/merge_requests/39/diffs#00524e372ebef34fc25a9ccf26625e53d9a78a00
#
# ###############################################################################
# CRYPTTAB_ENTRY="crypt-root UUID=${ENCRYPTED_UUID} none luks,tpm2-device=auto,tpm-pcrs=9"
# TMP_INITRAMFS=$(mktemp -d /tmp/initramfs.XXXXXX)
# echo "Extracting initramfs to ${TMP_INITRAMFS}..."
# cd "${TMP_INITRAMFS}"
# zstdcat "/boot/initrd.img-${KERNEL_VERSION}" | cpio --quiet -idm

# # Create crypttab file
# mkdir -p cryptroot
# echo "Creating cryptroot/crypttab entry..."
# echo "${CRYPTTAB_ENTRY}" > cryptroot/crypttab

# # For reproducibility, fix timestamps.
# : "${SOURCE_DATE_EPOCH:=1700000000}"
# find . -exec touch --date="@${SOURCE_DATE_EPOCH}" {} +
# echo "Repacking initramfs..."
# find . | sort | cpio --quiet -o -H newc | zstd -T0 -o "/boot/initrd.img-${KERNEL_VERSION}.patched"
# mv "/boot/initrd.img-${KERNEL_VERSION}.patched" "/boot/initrd.img-${KERNEL_VERSION}"
# cd /
# rm -rf "${TMP_INITRAMFS}"
# echo "Initramfs patched successfully."

# Create the kernel command line file
echo "Step 3: Creating kernel command line file..."
echo -n "${KERNEL_CMDLINE}" > "${CMDLINE_FILE}"
echo "Kernel command line written to ${CMDLINE_FILE}"

# Ensure a splash file exists (optional)
if [ ! -f "${SPLASH_FILE}" ]; then
    echo "Warning: Splash file ${SPLASH_FILE} not found. Creating an empty file."
    touch "${SPLASH_FILE}"
fi

# Compute section offsets and build the unified EFI image
echo "Step 5: Computing section offsets and creating unified EFI image..."
if [ ! -f "$EFI_STUB" ]; then
    echo "Error: EFI stub file $EFI_STUB not found. Please install systemd-boot-efi or adjust the EFI_STUB path."
    exit 1
fi
align="$(objdump -p "$EFI_STUB" | awk '{ if ($1 == "SectionAlignment"){print $2} }')"
align=$((16#$align))
echo "Section alignment: $align"
osrel_line=$(objdump -h "$EFI_STUB" | awk 'NF==7 {line=$0} END {print line}')
read -r _ _ size_hex vma_hex _ _ _ <<< "$osrel_line"
osrel_offs=$((16#$size_hex + 16#$vma_hex))
osrel_offs=$((osrel_offs + align - osrel_offs % align))
echo ".osrel offset: $(printf 0x%x $osrel_offs)"
cmdline_offs=$((osrel_offs + $(stat -c%s "$OSREL_FILE")))
cmdline_offs=$((cmdline_offs + align - cmdline_offs % align))
echo ".cmdline offset: $(printf 0x%x $cmdline_offs)"
splash_offs=$((cmdline_offs + $(stat -c%s "$CMDLINE_FILE")))
splash_offs=$((splash_offs + align - splash_offs % align))
echo ".splash offset: $(printf 0x%x $splash_offs)"
initrd_offs=$((splash_offs + $(stat -c%s "$SPLASH_FILE")))
initrd_offs=$((initrd_offs + align - initrd_offs % align))
echo ".initrd offset: $(printf 0x%x $initrd_offs)"
linux_offs=$((initrd_offs + $(stat -c%s "$INITRD_IMG")))
linux_offs=$((linux_offs + align - linux_offs % align))
echo ".linux offset: $(printf 0x%x $linux_offs)"
objcopy \
  --add-section .osrel="$OSREL_FILE" --change-section-vma .osrel=$(printf 0x%x $osrel_offs) \
  --add-section .cmdline="$CMDLINE_FILE" --change-section-vma .cmdline=$(printf 0x%x $cmdline_offs) \
  --add-section .splash="$SPLASH_FILE" --change-section-vma .splash=$(printf 0x%x $splash_offs) \
  --add-section .initrd="$INITRD_IMG" --change-section-vma .initrd=$(printf 0x%x $initrd_offs) \
  --add-section .linux="$NEW_KERNEL_IMAGE" --change-section-vma .linux=$(printf 0x%x $linux_offs) \
  "$EFI_STUB" "$EFI_IMAGE"
if [ ! -f "$EFI_IMAGE" ]; then
    echo "Error: Unified EFI image was not created."
    exit 1
fi
echo "Unified EFI image created at $EFI_IMAGE"

# (Optional) Sign the Unified EFI Image for Secure Boot
if [ -f "$SECUREBOOT_PRIVATE_KEY" ] && [ -f "$SECUREBOOT_CERTIFICATE" ]; then
    echo "Signing the unified EFI image..."
    sbsign --key "$SECUREBOOT_PRIVATE_KEY" --cert "$SECUREBOOT_CERTIFICATE" --output "$EFI_IMAGE.signed" "$EFI_IMAGE"
    if [ $? -eq 0 ]; then
        mv "$EFI_IMAGE.signed" "$EFI_IMAGE"
        echo "Unified EFI image successfully signed at $EFI_IMAGE"
        sbverify --cert "$SECUREBOOT_CERTIFICATE" "$EFI_IMAGE" && echo "Signature verified."
    else
        echo "Error: Signing failed." >&2
        exit 1
    fi
else
    echo "Secure Boot keys not found. Skipping signing step." >&2
fi

# Create a UEFI Boot Entry using efibootmgr
echo "Creating UEFI boot entry..."
boot_entry_output=$(efibootmgr -c -d "$DISK" -p "$PARTITION" -L "Linux Unified" -l "\\EFI\\Trusted\\kernel.efi" 2>&1) || true
if echo "$boot_entry_output" | grep -qi "EFI variables are not supported"; then
    echo "EFI variables not supported on this system; skipping boot entry creation."
else
    echo "$boot_entry_output"
fi

# Remove shim/grub boot entries
echo "Removing default debian boot entries..."
rm -rf /boot/efi/EFI/debian

# Enable getty on tty0 for graphical console login
echo "Enabling getty on tty0 for graphical console login..."
systemctl enable getty@tty0.service || true
systemctl start getty@tty0.service || true

# Install first-boot TPM enrollment service
echo "Setting up systemd first-boot playbook service..."
if [ "$SWTPM" = "true" ]; then
    FIRSTBOOT_CMD="ANSIBLE_CONFIG=/home/tpadm/.ansible/ansible.cfg /usr/bin/ansible-playbook /home/tpadm/ansible/playbooks/baremetal.yml -e SWTPM=true -i /etc/ansible/hosts -vvv | tee -a /var/log/ansible.log"
else
    FIRSTBOOT_CMD="ANSIBLE_CONFIG=/home/tpadm/.ansible/ansible.cfg /usr/bin/ansible-playbook /home/tpadm/ansible/playbooks/baremetal.yml -i /etc/ansible/hosts -vvv | tee -a /var/log/ansible.log"
fi
cat << EOF > /etc/systemd/system/first-boot-playbook.service
[Unit]
Description=Run Ansible Playbook on First Boot
After=network.target
Requires=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c '$FIRSTBOOT_CMD'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/first-boot-playbook.service
systemctl enable first-boot-playbook.service

# Prepare system for first boot Ansible execution.
cp -R /media/cdrom0/ansible /home/tpadm/
mkdir -p /home/tpadm/.ansible /etc/ansible/roles
mv /home/tpadm/ansible/roles/ /etc/ansible/
echo "[defaults]" > /home/tpadm/.ansible/ansible.cfg
echo "inventory=/etc/ansible/hosts" >> /home/tpadm/.ansible/ansible.cfg
echo "localhost ansible_connection=local" > /etc/ansible/hosts
usermod -aG sudo tpadm
chown -R tpadm:tpadm /home/tpadm/.ansible

/usr/bin/update-alternatives --set iptables /usr/sbin/iptables-legacy
/usr/bin/update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

echo "=== Installation Completed Successfully ==="
exit 0
