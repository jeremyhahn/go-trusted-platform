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

import "fmt"

// ErrRedfishRequest indicates a Redfish REST API request failure.
type ErrRedfishRequest struct {
	Method     string
	Path       string
	StatusCode int
	Message    string
	Cause      error
}

func (e ErrRedfishRequest) Error() string {
	msg := fmt.Sprintf("bmc: redfish %s %s failed", e.Method, e.Path)
	if e.StatusCode != 0 {
		msg = fmt.Sprintf("%s (HTTP %d)", msg, e.StatusCode)
	}
	if e.Message != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Message)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrRedfishRequest) Unwrap() error {
	return e.Cause
}

// ErrRedfishNotServiceRoot indicates an endpoint answered the service root
// path with something that is not a Redfish ServiceRoot, so it cannot be
// treated as a BMC.
type ErrRedfishNotServiceRoot struct {
	Address string
}

func (e ErrRedfishNotServiceRoot) Error() string {
	return fmt.Sprintf("bmc: %s did not answer %s as a Redfish service root", e.Address, redfishServiceRootPath)
}

// ErrPeerPinMismatch indicates a connection presented a different
// certificate than the one the conversation was pinned to, so it is not the
// endpoint that was identified.
type ErrPeerPinMismatch struct{}

func (ErrPeerPinMismatch) Error() string {
	return "bmc: endpoint presented a different certificate than the one identified"
}

// ErrRedfishDiscovery indicates a failure discovering Redfish service endpoints.
type ErrRedfishDiscovery struct {
	Resource string
	Cause    error
}

func (e ErrRedfishDiscovery) Error() string {
	msg := fmt.Sprintf("bmc: redfish discovery failed for %s", e.Resource)
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrRedfishDiscovery) Unwrap() error {
	return e.Cause
}

// ErrRedfishEmptyCollection indicates a Redfish collection contained no members.
type ErrRedfishEmptyCollection struct {
	Resource string
}

func (e ErrRedfishEmptyCollection) Error() string {
	return fmt.Sprintf("bmc: redfish collection %s has no members", e.Resource)
}

// ErrRedfishTransportInit indicates the shared Redfish HTTP transport
// could not be constructed. The Cause carries the underlying error from
// newRedfishTransport (typically a TLS or config validation failure).
type ErrRedfishTransportInit struct {
	Cause error
}

func (e ErrRedfishTransportInit) Error() string {
	return fmt.Sprintf("bmc: redfish transport init failed: %v", e.Cause)
}

func (e ErrRedfishTransportInit) Unwrap() error {
	return e.Cause
}
