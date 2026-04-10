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
	"context"
	"errors"
)

// virtualMediaBackends returns the ordered list of virtual media backends
// that the dispatcher will try, in priority order. Order is significant:
// the standard DMTF Redfish path is preferred, the Supermicro OEM Redfish
// path is tried second, and the legacy Supermicro CGI path (currently a
// documented stub) is the last resort. Construction is cheap so the list
// is built per-call instead of cached.
func (c *redfishClient) virtualMediaBackends() []virtualMediaBackend {
	return []virtualMediaBackend{
		newVmediaRedfishStd(c),
		newVmediaRedfishSmc(c),
		newVmediaSmcCGI(c),
	}
}

// isVirtualMediaFallthrough reports whether err is a fall-through signal
// (license-required or unsupported) that should cause the dispatcher to
// continue with the next backend rather than abort.
func isVirtualMediaFallthrough(err error) bool {
	var licErr ErrVirtualMediaLicenseRequired
	if errors.As(err, &licErr) {
		return true
	}
	var unsupErr ErrVirtualMediaUnsupported
	return errors.As(err, &unsupErr)
}

// MountVirtualMedia validates the spec and walks the backend chain until
// one succeeds. Fall-through errors (license-required, unsupported) move
// to the next backend; any other error short-circuits the chain.
func (c *redfishClient) MountVirtualMedia(ctx context.Context, spec *MediaSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	attempts := make([]VirtualMediaAttempt, 0, 3)
	for _, b := range c.virtualMediaBackends() {
		if !b.Supports(spec) {
			continue
		}
		err := b.Mount(ctx, spec)
		if err == nil {
			return nil
		}
		if isVirtualMediaFallthrough(err) {
			attempts = append(attempts, VirtualMediaAttempt{Backend: b.Name(), Err: err})
			continue
		}
		return ErrVirtualMediaBackendFailed{Backend: b.Name(), Cause: err}
	}
	return ErrVirtualMediaAllBackendsFailed{Attempts: attempts}
}

// UnmountVirtualMedia walks the backend chain calling Unmount until one
// succeeds. Backends without a spec to gate Supports() are tried in order.
func (c *redfishClient) UnmountVirtualMedia(ctx context.Context) error {
	attempts := make([]VirtualMediaAttempt, 0, 3)
	for _, b := range c.virtualMediaBackends() {
		err := b.Unmount(ctx)
		if err == nil {
			return nil
		}
		if isVirtualMediaFallthrough(err) {
			attempts = append(attempts, VirtualMediaAttempt{Backend: b.Name(), Err: err})
			continue
		}
		return ErrVirtualMediaBackendFailed{Backend: b.Name(), Cause: err}
	}
	return ErrVirtualMediaAllBackendsFailed{Attempts: attempts}
}

// virtualMediaStatusDispatch walks the backend chain calling Status until
// one returns a non-error result. It is used by VirtualMediaStatus on the
// redfishClient. The first non-fallthrough error short-circuits.
func (c *redfishClient) virtualMediaStatusDispatch(ctx context.Context) (*VirtualMediaInfo, error) {
	attempts := make([]VirtualMediaAttempt, 0, 3)
	for _, b := range c.virtualMediaBackends() {
		info, err := b.Status(ctx)
		if err == nil {
			return info, nil
		}
		if isVirtualMediaFallthrough(err) {
			attempts = append(attempts, VirtualMediaAttempt{Backend: b.Name(), Err: err})
			continue
		}
		return nil, ErrVirtualMediaBackendFailed{Backend: b.Name(), Cause: err}
	}
	return nil, ErrVirtualMediaAllBackendsFailed{Attempts: attempts}
}
