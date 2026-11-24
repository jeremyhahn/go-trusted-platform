package switchmgmt

import (
	"fmt"
	"regexp"
)

// maxPortNameLen caps an interface name; vendor interface names are far
// shorter.
const maxPortNameLen = 64

// portNameRegexp matches one interface identifier: a letter, then letters or
// '-', then a port number with up to three '/'-separated parts and one
// optional '.subinterface' (Eth1/3, Ethernet1/49/1, Eth1/1.100,
// port-channel10, mgmt0).
var portNameRegexp = regexp.MustCompile(`^[A-Za-z][A-Za-z-]{0,31}[0-9]+(/[0-9]+){0,3}(\.[0-9]+)?$`)

// ValidatePortName checks that port is a single interface name. The name is
// interpolated into switch CLI text, so it is checked before any SSH call:
// CLI separators, pipes, spaces, control characters and shell
// metacharacters are refused.
func ValidatePortName(port string) error {
	if len(port) > maxPortNameLen || !portNameRegexp.MatchString(port) {
		return ErrInvalidConfig{
			Field:  "port",
			Reason: fmt.Sprintf("%q is not a single interface name (letters, then digits, '/' and one optional '.subinterface')", port),
		}
	}
	return nil
}
