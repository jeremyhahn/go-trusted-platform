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

package daemon

import "fmt"

// ErrStatusMessage wraps a status error message from the server.
type ErrStatusMessage struct {
	Message string
}

func (e *ErrStatusMessage) Error() string {
	return e.Message
}

// ErrUnknownServiceType is returned when a service type string is not recognized.
type ErrUnknownServiceType struct {
	Type string
}

func (e *ErrUnknownServiceType) Error() string {
	return fmt.Sprintf("unknown service type: %s", e.Type)
}
