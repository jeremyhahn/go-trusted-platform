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

package device

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
)

// ID is a platform identifier as it appears on the device REST surface. It is
// the device package's wire id, which the shared request decoder uses too, so
// every REST listener encodes and decodes ids identically. See device.ID for
// why it marshals as a string and unmarshals from a string or a number.
type ID = device.ID

// ErrInvalidID reports an id that is neither a JSON string nor a JSON number
// holding an unsigned integer.
type ErrInvalidID = device.ErrInvalidID
