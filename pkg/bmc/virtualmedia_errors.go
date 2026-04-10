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

package bmc

import (
	"fmt"
	"strings"
)

// ErrVirtualMediaInvalidSpec indicates a MediaSpec failed validation.
type ErrVirtualMediaInvalidSpec struct {
	Field  string
	Reason string
}

func (e ErrVirtualMediaInvalidSpec) Error() string {
	return fmt.Sprintf("bmc: invalid virtual media spec: %s: %s", e.Field, e.Reason)
}

// ErrVirtualMediaUnsupported indicates a backend cannot service a request,
// either because the wire protocol is not implemented or because the BMC
// itself rejects the request as unsupported. The dispatcher treats this
// as a fall-through signal so the next backend in the chain may try.
type ErrVirtualMediaUnsupported struct {
	Backend string
	Vendor  string
	Reason  string
}

func (e ErrVirtualMediaUnsupported) Error() string {
	return fmt.Sprintf("bmc: virtual media unsupported by backend %q (vendor %q): %s",
		e.Backend, e.Vendor, e.Reason)
}

// ErrVirtualMediaLicenseRequired indicates the BMC rejected the request
// because a vendor license is missing (for example, Supermicro DCMS).
// The dispatcher treats this as a fall-through signal.
type ErrVirtualMediaLicenseRequired struct {
	Vendor  string
	License string
}

func (e ErrVirtualMediaLicenseRequired) Error() string {
	return fmt.Sprintf("bmc: virtual media requires %s license from %s", e.License, e.Vendor)
}

// ErrVirtualMediaBackendFailed wraps a fatal backend error that should
// short-circuit the dispatcher chain (i.e., not a license or unsupported
// signal but a real protocol failure).
type ErrVirtualMediaBackendFailed struct {
	Backend string
	Cause   error
}

func (e ErrVirtualMediaBackendFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bmc: virtual media backend %q failed: %v", e.Backend, e.Cause)
	}
	return fmt.Sprintf("bmc: virtual media backend %q failed", e.Backend)
}

func (e ErrVirtualMediaBackendFailed) Unwrap() error {
	return e.Cause
}

// VirtualMediaAttempt records one backend's attempt during dispatch.
type VirtualMediaAttempt struct {
	Backend string
	Err     error
}

// ErrVirtualMediaAllBackendsFailed indicates that every backend in the
// dispatch chain either declined the spec or returned a fall-through error.
type ErrVirtualMediaAllBackendsFailed struct {
	Attempts []VirtualMediaAttempt
}

func (e ErrVirtualMediaAllBackendsFailed) Error() string {
	if len(e.Attempts) == 0 {
		return "bmc: virtual media: no backend supported the request"
	}
	parts := make([]string, 0, len(e.Attempts))
	for _, a := range e.Attempts {
		parts = append(parts, fmt.Sprintf("%s: %v", a.Backend, a.Err))
	}
	return "bmc: virtual media: all backends failed: " + strings.Join(parts, "; ")
}

// ErrVirtualMediaAuth indicates an authentication failure during a virtual
// media operation against a specific backend.
type ErrVirtualMediaAuth struct {
	Backend string
	Cause   error
}

func (e ErrVirtualMediaAuth) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bmc: virtual media auth failed for backend %q: %v", e.Backend, e.Cause)
	}
	return fmt.Sprintf("bmc: virtual media auth failed for backend %q", e.Backend)
}

func (e ErrVirtualMediaAuth) Unwrap() error {
	return e.Cause
}
