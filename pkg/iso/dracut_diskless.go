package iso

import "github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"

// platformdDisklessRoot is the value the cmdline hook gives dracut's $root on
// a diskless node. It names no block device, so dracut's own root handlers
// leave it alone and the platformd hooks recognise it.
const platformdDisklessRoot = "platform-diskless"

// platformdBootModelShell decides which root the dracut hooks bring up. It
// reads the installer's command line embedded in the initramfs — the one the
// installer signed into the UKI — through disklessroot.BootModelShell, so a
// disk node's boot never takes the network root and a diskless node never
// waits on or unlocks a local one.
const platformdBootModelShell = disklessroot.BootModelShell + `
# Set dracut's root, rootok and rootfstype from the command line in the
# named file: the diskless root, or the local root= and rootfstype= it names.
# Usage: platformd_set_root <cmdline file>
platformd_set_root() {
    if [ "$(platformd_boot_model "$1")" = "diskless" ]; then
        root="` + platformdDisklessRoot + `"
        rootok=1
        info "PLATFORMD: Diskless root: the signed image, verified by dm-verity"
        return 0
    fi
    [ -f "$1" ] || return 0
    _root=$(tr ' \t' '\n\n' < "$1" | grep '^root=' | head -1)
    if [ -n "$_root" ]; then
        root="${_root#root=}"
        rootok=1
        info "PLATFORMD: Root device from $1: $root"
    fi
    _fstype=$(tr ' \t' '\n\n' < "$1" | grep '^rootfstype=' | head -1)
    if [ -n "$_fstype" ]; then
        rootfstype="${_fstype#rootfstype=}"
        info "PLATFORMD: Root fstype: $rootfstype"
    fi
}
`

// platformdRunInitrdShell runs platform-initrd for both roots. Its output is
// captured to a tmpfs file and replayed through dracut's info helper, so it
// lands on every BMC SOL channel and console redirect whatever /dev/console
// points at; the file goes away at switch_root.
const platformdRunInitrdShell = `# Run platform-initrd with the given arguments, replay its log, and return
# its exit status.
# Usage: platformd_run_initrd <args...>
platformd_run_initrd() {
    info "PLATFORMD: invoking platform-initrd $*"
    : > /run/platformd-initrd.log
    /usr/bin/platform-initrd "$@" --verbose < /dev/null > /run/platformd-initrd.log 2>&1
    _initrd_rc=$?
    info "PLATFORMD: platform-initrd exited rc=$_initrd_rc — log follows:"
    if [ -s /run/platformd-initrd.log ]; then
        while IFS= read -r line; do
            info "PLATFORMD-LOG: $line"
        done < /run/platformd-initrd.log
    else
        warn "PLATFORMD-LOG: (empty — binary produced no output)"
    fi
    return $_initrd_rc
}
`

// platformdDisklessRootShell brings up a diskless node's root. The network
// comes up from the installer's network.conf on the ESP, read-only (DHCP
// without one); platform-initrd then fetches the image the signed
// platform_roothash names, opens it under dm-verity with pinned parameters
// and overlays it with tmpfs at $NEWROOT. No local root is waited on or
// unlocked, and nothing on the disk is written.
const platformdDisklessRootShell = `# Write this node's own hostname, network and resolver settings into the root
# at $1, which is the writable tmpfs overlay, so they shadow the shared root's
# /etc/hostname, /etc/network/interfaces and /etc/resolv.conf. Every node of a
# media set boots the same root; without this they would all take its settings
# over the per-node network.conf. Reads the NET_* values platformd_network_up
# set. A file is removed first so a symlink in the shared root is replaced,
# never written through.
# Usage: platformd_seed_node_settings <root> <resolv.conf the initramfs uses>
platformd_seed_node_settings() {
    _seed_root="$1"
    mkdir -p "$_seed_root/etc/network" || return 1
    if [ -n "${NET_HOSTNAME:-}" ]; then
        rm -f "$_seed_root/etc/hostname"
        echo "$NET_HOSTNAME" > "$_seed_root/etc/hostname" || return 1
    fi
    if [ -s "$2" ]; then
        rm -f "$_seed_root/etc/resolv.conf"
        cat "$2" > "$_seed_root/etc/resolv.conf" || return 1
    fi
    _seed_iface="${NET_IFACE:-eth0}"
    rm -f "$_seed_root/etc/network/interfaces"
    {
        echo "auto lo"
        echo "iface lo inet loopback"
        echo "auto $_seed_iface"
        if [ "${NET_TYPE:-dhcp}" = "static" ] && [ -n "${NET_IP:-}" ] && [ -n "${NET_GW:-}" ]; then
            echo "iface $_seed_iface inet static"
            echo "    address $(platformd_static_cidr "$NET_IP" "${NET_PREFIX:-}" "${NET_MASK:-}")"
            echo "    gateway $NET_GW"
        else
            echo "iface $_seed_iface inet dhcp"
        fi
    } > "$_seed_root/etc/network/interfaces"
}

# Mount the diskless root at $NEWROOT and leave the unlock-done or
# unlock-failed marker the finished hook and the next initqueue pass read.
# Usage: platformd_diskless_root
platformd_diskless_root() {
    info "PLATFORMD: Diskless boot: fetching the signed root image"
    for _mod in loop dm_mod dm_verity squashfs overlay; do
        modprobe "$_mod" 2>/dev/null || true
    done

    _net_conf=""
    mkdir -p /boot/efi
    for _part in /dev/sda1 /dev/sdb1 /dev/nvme0n1p1 /dev/vda1 /dev/mmcblk0p1; do
        if [ -b "$_part" ] && mount -t vfat -o ro "$_part" /boot/efi 2>/dev/null; then
            if [ -f /boot/efi/tpm2/network.conf ]; then
                _net_conf=/boot/efi/tpm2/network.conf
                break
            fi
            umount /boot/efi 2>/dev/null
        fi
    done
    platformd_network_up "$_net_conf"
    if [ -n "$_net_conf" ]; then
        umount /boot/efi 2>/dev/null
    fi

    if [ ! -x /usr/bin/platform-initrd ]; then
        warn "PLATFORMD: platform-initrd not found at /usr/bin/platform-initrd"
        touch /tmp/platformd-unlock-failed
        return 0
    fi
    if platformd_run_initrd boot --diskless --root-mount "${NEWROOT:-/sysroot}" && mountpoint -q "${NEWROOT:-/sysroot}"; then
        info "PLATFORMD: Diskless root mounted at ${NEWROOT:-/sysroot}"
        if platformd_seed_node_settings "${NEWROOT:-/sysroot}" /etc/resolv.conf; then
            touch /tmp/platformd-unlock-done
        else
            warn "PLATFORMD: Could not write this node's settings into the diskless root"
            touch /tmp/platformd-unlock-failed
        fi
    else
        warn "PLATFORMD: Diskless root failed; the node has no root to boot"
        touch /tmp/platformd-unlock-failed
    fi
    return 0
}
`
