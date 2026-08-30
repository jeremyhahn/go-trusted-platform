package iso

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
