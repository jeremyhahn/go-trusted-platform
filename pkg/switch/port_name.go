// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

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
