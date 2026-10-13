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

package mcp

import (
	"fmt"

	"google.golang.org/grpc/status"
)

// =============================================================================
// CA Error Types
// =============================================================================

// CAError represents a CA operation error.
type CAError struct {
	Code    string
	Message string
}

func (e *CAError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// GRPCStatus classifies the error by its Code (codeClass), so the MCP
// server answers it with the matching JSON-RPC code.
func (e *CAError) GRPCStatus() *status.Status {
	return codeStatus(e.Code, e.Error())
}

// CA error instances
var (
	// ErrCAServiceUnavailable indicates the CA service is not available.
	ErrCAServiceUnavailable = &CAError{
		Code:    "CA_SERVICE_UNAVAILABLE",
		Message: "certificate authority service is not available",
	}

	// ErrCANotInitialized indicates the CA is not initialized.
	ErrCANotInitialized = &CAError{
		Code:    "CA_NOT_INITIALIZED",
		Message: "certificate authority is not initialized",
	}

	// ErrCACommonNameRequired indicates a common name is required.
	ErrCACommonNameRequired = &CAError{
		Code:    "CA_COMMON_NAME_REQUIRED",
		Message: "common name is required for certificate issuance",
	}

	// ErrCASerialRequired indicates a serial number is required.
	ErrCASerialRequired = &CAError{
		Code:    "CA_SERIAL_REQUIRED",
		Message: "certificate serial number is required",
	}

	// ErrCACertificateNotFound indicates a certificate was not found.
	ErrCACertificateNotFound = &CAError{
		Code:    "CA_CERTIFICATE_NOT_FOUND",
		Message: "certificate not found",
	}

	// ErrCACertificateRequired indicates a certificate is required.
	ErrCACertificateRequired = &CAError{
		Code:    "CA_CERTIFICATE_REQUIRED",
		Message: "certificate (PEM or DER) is required for verification",
	}

	// ErrCAInvalidDEREncoding indicates invalid DER encoding.
	ErrCAInvalidDEREncoding = &CAError{
		Code:    "CA_INVALID_DER_ENCODING",
		Message: "invalid base64 DER certificate encoding",
	}

	// ErrCAInvalidValidityPeriod indicates invalid validity period.
	ErrCAInvalidValidityPeriod = &CAError{
		Code:    "CA_INVALID_VALIDITY_PERIOD",
		Message: "validity period must be greater than zero",
	}
)
