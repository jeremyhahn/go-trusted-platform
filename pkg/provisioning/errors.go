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

package provisioning

import "errors"

var (
	// ErrProfileFetchFailed is returned when the profile API request fails
	ErrProfileFetchFailed = errors.New("provisioning: failed to fetch device profile")

	// ErrActivationFailed is returned when the activation API request fails
	ErrActivationFailed = errors.New("provisioning: failed to activate device")

	// ErrMissingCertificate is returned when IDevID certificate is not available
	ErrMissingCertificate = errors.New("provisioning: IDevID certificate not available")

	// ErrMissingPrivateKey is returned when IDevID private key is not available
	ErrMissingPrivateKey = errors.New("provisioning: IDevID private key not available")

	// ErrMissingCABundle is returned when CA bundle is not available
	ErrMissingCABundle = errors.New("provisioning: CA bundle not available")

	// ErrInvalidResponse is returned when the server response is invalid
	ErrInvalidResponse = errors.New("provisioning: invalid server response")

	// ErrServerError is returned when the server returns an error status
	ErrServerError = errors.New("provisioning: server returned error")

	// ErrConnectionFailed is returned when the connection to the server fails
	ErrConnectionFailed = errors.New("provisioning: connection to server failed")

	// ErrTimeout is returned when the request times out
	ErrTimeout = errors.New("provisioning: request timed out")
)
