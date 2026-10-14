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

// ErrMissingZoneName is returned when zone name is required but not provided
type ErrMissingZoneName struct{}

func (e ErrMissingZoneName) Error() string {
	return "zone name is required"
}

// ErrMissingRecordName is returned when record name is required but not provided
type ErrMissingRecordName struct{}

func (e ErrMissingRecordName) Error() string {
	return "record name is required"
}

// ErrMissingRecordType is returned when record type is required but not provided
type ErrMissingRecordType struct{}

func (e ErrMissingRecordType) Error() string {
	return "record type is required"
}

// ErrInvalidRequestBody is returned when the request body is invalid
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	return fmt.Sprintf("invalid request body: %s", e.Reason)
}

// ErrInvalidRecordType is returned when an invalid record type is provided
type ErrInvalidRecordType struct {
	Type string
}

func (e ErrInvalidRecordType) Error() string {
	return fmt.Sprintf("invalid record type: %s", e.Type)
}

// ErrRecordNotFound is returned when a zone holds no record of the given type and name
type ErrRecordNotFound struct {
	Type string
	Name string
}

func (e ErrRecordNotFound) Error() string {
	return fmt.Sprintf("record not found: %s %s", e.Type, e.Name)
}

// ErrMissingFQDN is returned when FQDN is required but not provided
type ErrMissingFQDN struct{}

func (e ErrMissingFQDN) Error() string {
	return "fqdn is required"
}

// ErrMissingIP is returned when IP address is required but not provided
type ErrMissingIP struct{}

func (e ErrMissingIP) Error() string {
	return "ip address is required"
}
