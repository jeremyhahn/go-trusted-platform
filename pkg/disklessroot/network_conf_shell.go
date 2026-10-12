package disklessroot

// NetworkConfShell is the POSIX shell function that reads the installer's
// network.conf. The file sits on a FAT ESP anyone with the disk can edit, and
// it is read by the initramfs and by the root's init as root, so it is never
// sourced: a value such as $(cmd) or a trailing "; cmd" would run. Each line is
// split at the first "=", the key must be on the allow-list, and the value
// (one pair of surrounding double quotes removed) may hold only letters,
// digits, ".", "_", ":", "/", "-" and spaces. Any other line is reported on
// stderr and skipped, and the function returns 1; the values on the lines that
// passed are kept. POSIX sh only: this runs under busybox ash.
//
// Usage: platformd_load_network_conf <network.conf path>
const NetworkConfShell = `# Load the allow-listed KEY=value lines of a network.conf without sourcing it.
# Usage: platformd_load_network_conf <network.conf path>
platformd_load_network_conf() {
    INTERFACE=""
    TYPE=""
    IPV4_ADDRESS=""
    IPV4_PREFIX=""
    IPV4_NETMASK=""
    IPV4_GATEWAY=""
    DNS=""
    HOSTNAME=""
    _nc_rc=0
    while IFS= read -r _nc_line || [ -n "$_nc_line" ]; do
        case "$_nc_line" in
            ''|'#'*) continue ;;
            *=*) ;;
            *) echo "platformd: network.conf: ignoring a line that is not KEY=value" >&2; _nc_rc=1; continue ;;
        esac
        _nc_key="${_nc_line%%=*}"
        _nc_val="${_nc_line#*=}"
        case "$_nc_val" in
            \"*\") _nc_val="${_nc_val#\"}"; _nc_val="${_nc_val%\"}" ;;
        esac
        case "$_nc_val" in
            *[!A-Za-z0-9._:/' '-]*)
                echo "platformd: network.conf: ignoring a value that has characters outside [A-Za-z0-9._:/ -]" >&2
                _nc_rc=1
                continue ;;
        esac
        case "$_nc_key" in
            INTERFACE) INTERFACE="$_nc_val" ;;
            TYPE) TYPE="$_nc_val" ;;
            IPV4_ADDRESS) IPV4_ADDRESS="$_nc_val" ;;
            IPV4_PREFIX) IPV4_PREFIX="$_nc_val" ;;
            IPV4_NETMASK) IPV4_NETMASK="$_nc_val" ;;
            IPV4_GATEWAY) IPV4_GATEWAY="$_nc_val" ;;
            DNS) DNS="$_nc_val" ;;
            HOSTNAME) HOSTNAME="$_nc_val" ;;
            *) echo "platformd: network.conf: ignoring an unknown key" >&2; _nc_rc=1 ;;
        esac
    done < "$1"
    return $_nc_rc
}
`
