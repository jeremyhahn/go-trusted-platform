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

// Package switchsdk provides a client for physical switch management operations.
package switchsdk

import "fmt"

// ErrNilHTTPClient is returned when a nil HTTP client is provided.
type ErrNilHTTPClient struct{}

func (e ErrNilHTTPClient) Error() string {
	return "switchsdk: http client is nil"
}

// ErrEmptyBaseURL is returned when an empty base URL is provided.
type ErrEmptyBaseURL struct{}

func (e ErrEmptyBaseURL) Error() string {
	return "switchsdk: base URL is empty"
}

// ErrRequestFailed is returned when an HTTP request fails.
type ErrRequestFailed struct {
	Method string
	URL    string
	Cause  error
}

func (e ErrRequestFailed) Error() string {
	return fmt.Sprintf("switchsdk: %s %s failed: %v", e.Method, e.URL, e.Cause)
}

func (e ErrRequestFailed) Unwrap() error {
	return e.Cause
}

// ErrUnexpectedStatus is returned when the server returns an unexpected HTTP status.
type ErrUnexpectedStatus struct {
	StatusCode int
	Body       string
}

func (e ErrUnexpectedStatus) Error() string {
	return fmt.Sprintf("switchsdk: unexpected HTTP status %d: %s", e.StatusCode, e.Body)
}

// ErrResponseDecodeFailed is returned when decoding a server response fails.
type ErrResponseDecodeFailed struct {
	Cause error
}

func (e ErrResponseDecodeFailed) Error() string {
	return fmt.Sprintf("switchsdk: failed to decode response: %v", e.Cause)
}

func (e ErrResponseDecodeFailed) Unwrap() error {
	return e.Cause
}

// ErrRequestEncodeFailed is returned when encoding a request body fails.
type ErrRequestEncodeFailed struct {
	Cause error
}

func (e ErrRequestEncodeFailed) Error() string {
	return fmt.Sprintf("switchsdk: failed to encode request: %v", e.Cause)
}

func (e ErrRequestEncodeFailed) Unwrap() error {
	return e.Cause
}

// ErrRequestBuildFailed is returned when building an HTTP request fails.
type ErrRequestBuildFailed struct {
	Cause error
}

func (e ErrRequestBuildFailed) Error() string {
	return fmt.Sprintf("switchsdk: failed to build request: %v", e.Cause)
}

func (e ErrRequestBuildFailed) Unwrap() error {
	return e.Cause
}

// ErrListPortsFailed is returned when listing ports fails.
type ErrListPortsFailed struct {
	Switch string
	Cause  error
}

func (e ErrListPortsFailed) Error() string {
	return fmt.Sprintf("switchsdk: list ports failed for switch %q: %v", e.Switch, e.Cause)
}

func (e ErrListPortsFailed) Unwrap() error {
	return e.Cause
}

// ErrGetPortStatusFailed is returned when getting port status fails.
type ErrGetPortStatusFailed struct {
	Switch string
	Port   string
	Cause  error
}

func (e ErrGetPortStatusFailed) Error() string {
	return fmt.Sprintf("switchsdk: get port status failed for switch %q port %q: %v",
		e.Switch, e.Port, e.Cause)
}

func (e ErrGetPortStatusFailed) Unwrap() error {
	return e.Cause
}

// ErrSetPortVLANFailed is returned when setting a port VLAN fails.
type ErrSetPortVLANFailed struct {
	Switch string
	Port   string
	VLANID uint16
	Cause  error
}

func (e ErrSetPortVLANFailed) Error() string {
	return fmt.Sprintf("switchsdk: set vlan %d failed for switch %q port %q: %v",
		e.VLANID, e.Switch, e.Port, e.Cause)
}

func (e ErrSetPortVLANFailed) Unwrap() error {
	return e.Cause
}

// ErrEnablePortFailed is returned when enabling a port fails.
type ErrEnablePortFailed struct {
	Switch string
	Port   string
	Cause  error
}

func (e ErrEnablePortFailed) Error() string {
	return fmt.Sprintf("switchsdk: enable port failed for switch %q port %q: %v",
		e.Switch, e.Port, e.Cause)
}

func (e ErrEnablePortFailed) Unwrap() error {
	return e.Cause
}

// ErrDisablePortFailed is returned when disabling a port fails.
type ErrDisablePortFailed struct {
	Switch string
	Port   string
	Cause  error
}

func (e ErrDisablePortFailed) Error() string {
	return fmt.Sprintf("switchsdk: disable port failed for switch %q port %q: %v",
		e.Switch, e.Port, e.Cause)
}

func (e ErrDisablePortFailed) Unwrap() error {
	return e.Cause
}
