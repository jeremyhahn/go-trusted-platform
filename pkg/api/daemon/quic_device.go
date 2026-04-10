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

// =============================================================================
// Device QUIC Request/Response Types
// =============================================================================

// DeviceRegisterRequest represents a device registration request
type DeviceRegisterRequest struct {
	ID         uint64 `codec:"id"`
	Serial     string `codec:"serial"`
	Model      string `codec:"model"`
	AttestPub  string `codec:"attest_pub"`
	SigningPub string `codec:"signing_pub"`
	EKCert     string `codec:"ek_cert"`
	HashAlgoID int    `codec:"hash_algo_id"`
}

// DeviceRegisterResponse represents a device registration response
type DeviceRegisterResponse struct {
	ID        uint64 `codec:"id"`
	Serial    string `codec:"serial"`
	Model     string `codec:"model"`
	Timestamp int64  `codec:"timestamp"`
}

// DeviceUnregisterRequest represents a device unregistration request
type DeviceUnregisterRequest struct {
	ID uint64 `codec:"id"`
}

// DeviceUnregisterResponse represents a device unregistration response
type DeviceUnregisterResponse struct {
	ID        uint64 `codec:"id"`
	Deleted   bool   `codec:"deleted"`
	Timestamp int64  `codec:"timestamp"`
}

// DeviceGetRequest represents a get device request
type DeviceGetRequest struct {
	ID uint64 `codec:"id"`
}

// DeviceGetResponse represents a get device response
type DeviceGetResponse struct {
	ID        uint64 `codec:"id"`
	Serial    string `codec:"serial"`
	Model     string `codec:"model"`
	State     string `codec:"state"`
	Timestamp int64  `codec:"timestamp"`
}

// DeviceListRequest represents a list devices request
type DeviceListRequest struct {
	Limit  int `codec:"limit"`
	Offset int `codec:"offset"`
}

// DeviceListResponse represents a list devices response
type DeviceListResponse struct {
	Devices   []*DeviceSummary `codec:"devices"`
	Total     int              `codec:"total"`
	Timestamp int64            `codec:"timestamp"`
}

// DeviceSummary represents a device summary for listing
type DeviceSummary struct {
	ID     uint64 `codec:"id"`
	Serial string `codec:"serial"`
	Model  string `codec:"model"`
	State  string `codec:"state"`
}

// DeviceUpdateRequest represents a device update request
type DeviceUpdateRequest struct {
	ID     uint64 `codec:"id"`
	Serial string `codec:"serial"`
	Model  string `codec:"model"`
}

// DeviceUpdateResponse represents a device update response
type DeviceUpdateResponse struct {
	ID        uint64 `codec:"id"`
	Serial    string `codec:"serial"`
	Model     string `codec:"model"`
	Timestamp int64  `codec:"timestamp"`
}

// =============================================================================
// Device Profile QUIC Request/Response Types
// =============================================================================

// DeviceProfileGetRequest represents a get device profile request
type DeviceProfileGetRequest struct {
	ID uint64 `codec:"id"`
}

// DeviceProfileGetResponse represents a get device profile response
type DeviceProfileGetResponse struct {
	ID   uint64 `codec:"id"`
	Name string `codec:"name"`
	Role string `codec:"role"`
}

// DeviceProfileCreateRequest represents a create device profile request
type DeviceProfileCreateRequest struct {
	Name  string `codec:"name"`
	Model string `codec:"model"`
	Role  string `codec:"role"`
}

// DeviceProfileDeleteRequest represents a delete device profile request
type DeviceProfileDeleteRequest struct {
	ID uint64 `codec:"id"`
}

// DeviceProfileSummary represents a device profile summary for listing
type DeviceProfileSummary struct {
	ID   uint64 `codec:"id"`
	Name string `codec:"name"`
	Role string `codec:"role"`
}

// DeviceProfileListResponse represents a list device profiles response
type DeviceProfileListResponse struct {
	Profiles  []*DeviceProfileSummary `codec:"profiles"`
	Total     int                     `codec:"total"`
	Timestamp int64                   `codec:"timestamp"`
}
