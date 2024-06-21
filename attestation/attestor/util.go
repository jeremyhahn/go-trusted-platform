package attestor

import (
	"net"
	"strings"
)

func parseVerifierIP(addr net.Addr) string {
	pieces := strings.Split(addr.String(), ":")
	return pieces[0]
}
