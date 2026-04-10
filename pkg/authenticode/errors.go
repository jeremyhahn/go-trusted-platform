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

package authenticode

import "fmt"

// ErrRFC3161NotImplemented indicates that RFC3161 timestamping was requested
// but is not yet implemented.
type ErrRFC3161NotImplemented struct {
	URL string
}

// Error returns the error message.
func (e ErrRFC3161NotImplemented) Error() string {
	return fmt.Sprintf("authenticode: RFC3161 timestamping not implemented (TSA URL: %s)", e.URL)
}
