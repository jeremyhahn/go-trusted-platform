package iso

import "github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"

// platformdStaticCIDRShell is spliced into the dracut unlock hook. It turns
// whatever /boot/efi/tpm2/network.conf carries into exactly one "addr/prefix"
// for ip(8). The prefix is taken, in order, from IPV4_PREFIX, from a CIDR
// suffix on IPV4_ADDRESS, from a dotted IPV4_NETMASK, and finally defaults to
// /24. Any suffix already on the address is stripped first, so the result is
// the same whether the installer wrote "a.b.c.d" or "a.b.c.d/24" — the
// "a.b.c.d/24/24" form that left eth0 without an address can no longer occur.
// A malformed prefix (non-numeric, out of range, doubled) falls back to the
// next source rather than being applied. POSIX sh only: this runs under
// busybox ash inside the initramfs.
const platformdStaticCIDRShell = `# Print "<ip>/<prefix>" for ip addr add from the network.conf fields
# IPV4_ADDRESS, IPV4_PREFIX and IPV4_NETMASK, applying the prefix once.
# Usage: platformd_static_cidr <address[/prefix]> <prefix> <netmask>
platformd_static_cidr() {
    _ip="${1%%/*}"
    _prefix="$2"
    _mask="$3"
    _suffix=""
    case "$1" in
        */*) _suffix="${1#*/}" ;;
    esac
    if ! platformd_valid_prefix "$_prefix"; then
        _prefix="$_suffix"
    fi
    if ! platformd_valid_prefix "$_prefix"; then
        case "$_mask" in
            255.255.255.255) _prefix="32" ;;
            255.255.255.254) _prefix="31" ;;
            255.255.255.252) _prefix="30" ;;
            255.255.255.248) _prefix="29" ;;
            255.255.255.240) _prefix="28" ;;
            255.255.255.224) _prefix="27" ;;
            255.255.255.192) _prefix="26" ;;
            255.255.255.128) _prefix="25" ;;
            255.255.255.0)   _prefix="24" ;;
            255.255.254.0)   _prefix="23" ;;
            255.255.252.0)   _prefix="22" ;;
            255.255.248.0)   _prefix="21" ;;
            255.255.240.0)   _prefix="20" ;;
            255.255.224.0)   _prefix="19" ;;
            255.255.192.0)   _prefix="18" ;;
            255.255.128.0)   _prefix="17" ;;
            255.255.0.0)     _prefix="16" ;;
            255.0.0.0)       _prefix="8" ;;
            *)               _prefix="" ;;
        esac
    fi
    if ! platformd_valid_prefix "$_prefix"; then
        _prefix="24"
    fi
    echo "$_ip/$_prefix"
}

# Succeed when $1 is a decimal prefix length in 0..32.
platformd_valid_prefix() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -le 32 ]
}
`

// platformdNetworkUpShell is spliced into the dracut unlock hook after
// platformdStaticCIDRShell. It brings one interface up from a network.conf the
// installer wrote — static when the file says so, DHCP otherwise or when there
// is no file — and sets the hostname the IAK/IDevID certificates are named
// after. The firstboot path calls it for diagnostics; the diskless path needs
// it to fetch its root.
const platformdNetworkUpShell = disklessroot.NetworkConfShell + `
# Bring the network up from a network.conf, or DHCP on eth0 without one.
# Usage: platformd_network_up <network.conf path or "">
platformd_network_up() {
    NETWORK_CONF="$1"

    # Load all common NIC drivers (virtual and bare metal)
    for drv in virtio_net e1000 e1000e igb ixgbe i40e ice mlx5_core bnxt_en; do
        modprobe "$drv" 2>/dev/null || true
    done

    NET_IFACE=""
    NET_TYPE=""
    NET_IP=""
    NET_PREFIX=""
    NET_MASK=""
    NET_GW=""

    if [ -n "$NETWORK_CONF" ] && [ -f "$NETWORK_CONF" ]; then
        info "PLATFORMD: Reading network config from $NETWORK_CONF"
        platformd_load_network_conf "$NETWORK_CONF" || warn "PLATFORMD: Ignored lines in $NETWORK_CONF that are not allow-listed KEY=value"
        NET_IFACE="${INTERFACE:-eth0}"
        NET_TYPE="${TYPE:-dhcp}"
        NET_IP="${IPV4_ADDRESS:-}"
        NET_PREFIX="${IPV4_PREFIX:-}"
        NET_MASK="${IPV4_NETMASK:-}"
        NET_GW="${IPV4_GATEWAY:-}"
        NET_DNS="${DNS:-8.8.8.8}"
        NET_HOSTNAME="${HOSTNAME:-}"
        info "PLATFORMD: Network config: iface=$NET_IFACE type=$NET_TYPE ip=$NET_IP gw=$NET_GW dns=$NET_DNS hostname=$NET_HOSTNAME"

        if [ -n "$NET_HOSTNAME" ]; then
            info "PLATFORMD: Setting hostname to $NET_HOSTNAME"
            echo "$NET_HOSTNAME" > /etc/hostname
            hostname "$NET_HOSTNAME" 2>/dev/null || true
        fi
    else
        info "PLATFORMD: No network.conf found, will try DHCP"
        NET_IFACE="eth0"
        NET_TYPE="dhcp"
        NET_DNS="8.8.8.8"
    fi

    for i in 1 2 3 4 5; do
        if ip link show "$NET_IFACE" >/dev/null 2>&1; then
            break
        fi
        info "PLATFORMD: Waiting for network interface $NET_IFACE... ($i/5)"
        sleep 1
    done

    if ip link show "$NET_IFACE" >/dev/null 2>&1; then
        info "PLATFORMD: Configuring network interface $NET_IFACE..."
        ip link set "$NET_IFACE" up

        if [ "$NET_TYPE" = "static" ] && [ -n "$NET_IP" ] && [ -n "$NET_GW" ]; then
            NET_CIDR=$(platformd_static_cidr "$NET_IP" "$NET_PREFIX" "$NET_MASK")
            info "PLATFORMD: Configuring static IP: $NET_CIDR gateway: $NET_GW"
            ip addr add "$NET_CIDR" dev "$NET_IFACE" 2>/dev/null || true
            ip route add default via "$NET_GW" 2>/dev/null || true

            info "PLATFORMD: Configuring DNS: $NET_DNS"
            : > /etc/resolv.conf
            for dns_server in $NET_DNS; do
                echo "nameserver $dns_server" >> /etc/resolv.conf
            done
        else
            info "PLATFORMD: Configuring DHCP on $NET_IFACE..."
            udhcpc -i "$NET_IFACE" -n -q -t 5 2>/dev/null || true
            if [ ! -s /etc/resolv.conf ]; then
                info "PLATFORMD: DHCP did not configure DNS, using fallback"
                echo "nameserver 8.8.8.8" > /etc/resolv.conf
            fi
        fi

        ip addr show "$NET_IFACE" 2>/dev/null | grep inet || warn "PLATFORMD: No IP address on $NET_IFACE"
        info "PLATFORMD: DNS configuration:"
        cat /etc/resolv.conf 2>/dev/null || warn "PLATFORMD: No resolv.conf"

        if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
            info "PLATFORMD: Network connectivity confirmed"
        else
            warn "PLATFORMD: No network connectivity from the initramfs"
        fi
    else
        warn "PLATFORMD: Network interface $NET_IFACE not found"
    fi
}
`

// platformdInstallNetworkShell installs what platformd_network_up runs into
// the initramfs, from module-setup.sh's install(). The installer omits dracut's
// network modules, so nothing else carries them. busybox udhcpc only obtains
// a lease: the default.script it runs (busybox's, from the root the initramfs
// is built in) puts the address, route and resolver on the interface with ip,
// cut, chmod and mv. A diskless node fetches its root over that network, so a
// missing piece fails its initramfs build instead of producing a node that
// cannot boot; a disk install only warns, since its initramfs needs the
// network for a diagnostic alone.
const platformdInstallNetworkShell = disklessroot.BootModelShell + `
# Install the DHCP client, the script that applies its lease and the tools
# both run from the root at $1. Returns 1 when one is missing and the command
# line in $2 selects the diskless root.
# Usage: platformd_install_network <build root, "" for /> <cmdline file>
platformd_install_network() {
    _net_missing=""
    for _bin in udhcpc ip cut chmod mv; do
        inst_multiple "$_bin" 2>/dev/null || _net_missing="$_net_missing $_bin"
    done
    for _bin in ping hostname; do
        inst_multiple "$_bin" 2>/dev/null || dinfo "PLATFORMD: optional network tool $_bin not found, skipping"
    done
    if [ -f "$1/usr/share/udhcpc/default.script" ]; then
        inst_simple "$1/usr/share/udhcpc/default.script" /usr/share/udhcpc/default.script ||
            _net_missing="$_net_missing default.script"
    else
        _net_missing="$_net_missing default.script"
    fi
    if [ -f "$1/etc/udhcpc/udhcpc.conf" ]; then
        inst_simple "$1/etc/udhcpc/udhcpc.conf" /etc/udhcpc/udhcpc.conf ||
            _net_missing="$_net_missing udhcpc.conf"
    fi
    [ -z "$_net_missing" ] && return 0
    if [ "$(platformd_boot_model "$2")" = "diskless" ]; then
        derror "PLATFORMD: a diskless node fetches its root over the network, and the initramfs lacks:$_net_missing"
        return 1
    fi
    dwarn "PLATFORMD: the initramfs lacks:$_net_missing; the first-boot network diagnostic may not come up"
    return 0
}
`
