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

package dns

import "fmt"

// ErrInvalidRecordType is returned when a path or query record type names no
// RecordType.
type ErrInvalidRecordType struct {
	Type string
}

func (e *ErrInvalidRecordType) Error() string {
	return fmt.Sprintf("invalid record type: %s", e.Type)
}

// ErrRecordNotFound is returned when a zone holds no record of the given type and name
type ErrRecordNotFound struct {
	Type string
	Name string
}

func (e *ErrRecordNotFound) Error() string {
	return fmt.Sprintf("record not found: %s %s", e.Type, e.Name)
}
