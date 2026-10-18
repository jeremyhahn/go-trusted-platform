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

package luks

import "os"

// geteuid returns the effective user ID checkRoot tests.
// Overridable seam for tests; defaults to os.Geteuid.
var geteuid = os.Geteuid

// checkRoot verifies the current process is running as root. LUKS2 header IO
// requires CAP_SYS_ADMIN which in practice means running as UID 0.
//
// This helper lived previously in the fido2 package alongside LUKS code; it
// now lives next to its only remaining caller.
func checkRoot() error {
	if geteuid() != 0 {
		return ErrRootRequired{}
	}
	return nil
}
