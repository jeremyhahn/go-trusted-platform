package installer

import (
	"net"
	"strconv"
	"strings"
)

// defaultStaticPrefixLen is the IPv4 prefix length network.conf carries when
// the interface declares neither a CIDR suffix nor a netmask.
const defaultStaticPrefixLen = 24

// StaticAddressError reports a static interface address that cannot be
// expressed as the bare address plus prefix length that network.conf carries.
type StaticAddressError struct {
	Address string
	Netmask string
	Reason  string
}

// Error implements the error interface.
func (e *StaticAddressError) Error() string {
	return "installer: static address " + strconv.Quote(e.Address) + " netmask " +
		strconv.Quote(e.Netmask) + ": " + e.Reason
}

// firstbootStaticAddress splits an interface's static IPv4 address into the
// bare address and prefix length the initramfs applies. The prefix comes from
// the CIDR suffix when the address carries one, otherwise from the dotted
// netmask, otherwise defaultStaticPrefixLen. The result never carries a
// slash, so the dracut hook can append its own exactly once.
func firstbootStaticAddress(address, netmask string) (string, int, error) {
	bare, suffix, hasSuffix := strings.Cut(address, "/")
	ip := net.ParseIP(bare)
	if ip == nil || ip.To4() == nil {
		return "", 0, &StaticAddressError{Address: address, Netmask: netmask, Reason: "not an IPv4 address"}
	}
	bare = ip.To4().String()

	if hasSuffix {
		prefix, err := strconv.Atoi(suffix)
		if err != nil || prefix < 0 || prefix > 32 {
			return "", 0, &StaticAddressError{Address: address, Netmask: netmask, Reason: "prefix length must be 0-32"}
		}
		return bare, prefix, nil
	}

	if netmask == "" {
		return bare, defaultStaticPrefixLen, nil
	}
	mask := net.ParseIP(netmask)
	if mask == nil || mask.To4() == nil {
		return "", 0, &StaticAddressError{Address: address, Netmask: netmask, Reason: "netmask is not dotted-quad"}
	}
	prefix, bits := net.IPMask(mask.To4()).Size()
	if bits == 0 {
		return "", 0, &StaticAddressError{Address: address, Netmask: netmask, Reason: "netmask is not contiguous"}
	}
	return bare, prefix, nil
}
