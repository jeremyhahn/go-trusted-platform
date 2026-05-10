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

package smc

import "os"

// readFile is a thin seam over os.ReadFile so tests can substitute it
// via the file variable. Defined in its own file to keep cgi_cert.go
// focused on protocol logic.
var readFile = os.ReadFile
