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

package appservices

import "fmt"

// Service names, as they appear in errors and in the not-configured reason
// every transport carries.
const (
	ServiceCache         = "cache"
	ServiceScheduler     = "scheduler"
	ServiceMessaging     = "messaging"
	ServiceObjectStorage = "objectstorage"
)

// ErrNotConfigured reports that the composed SDK does not serve the service
// on this node: the SDK has not started, or it does not expose the group.
type ErrNotConfigured struct {
	Service string
}

func (e ErrNotConfigured) Error() string {
	return fmt.Sprintf("%s is not served by the go-quicbaas SDK on this node", e.Service)
}

// ErrInvalidArgument reports a request the service refuses before it
// reaches the SDK.
type ErrInvalidArgument struct {
	Service string
	Field   string
	Reason  string
}

func (e ErrInvalidArgument) Error() string {
	return fmt.Sprintf("%s: invalid %s: %s", e.Service, e.Field, e.Reason)
}

// ErrCallFailed wraps an error the SDK returned.
type ErrCallFailed struct {
	Service string
	Op      string
	Cause   error
}

func (e ErrCallFailed) Error() string {
	return fmt.Sprintf("%s %s failed: %v", e.Service, e.Op, e.Cause)
}

func (e ErrCallFailed) Unwrap() error {
	return e.Cause
}
