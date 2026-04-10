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

// Package auth provides mTLS-based authentication for the Trusted Platform.
//
// The auth package implements certificate-based authentication using mutual TLS,
// extracting identity information from client certificates and validating them
// against trusted Certificate Authority chains. It supports:
//
//   - Certificate chain validation against trusted root and intermediate CAs
//   - Identity extraction from various certificate fields (CN, Email, Serial, etc.)
//   - Tenant extraction for multi-tenant deployments
//   - IDevID/IAK certificate validation for TPM-attested devices
//   - Certificate revocation checking via CRL
//
// The package is designed to work with the go-trusted-ca CertificateAuthority
// interface for certificate validation and the IAM middleware for session
// management.
//
// # Basic Usage
//
// Create an MTLSAdapter with trusted root certificates:
//
//	adapter, err := auth.NewMTLSAdapter(
//	    logger,
//	    ca,
//	    auth.WithIdentityField(auth.IdentityFieldEmail),
//	    auth.WithTenantField(auth.IdentityFieldOrganization),
//	)
//
// Authenticate a client certificate:
//
//	identity, err := adapter.Authenticate(ctx, clientCert)
//	if err != nil {
//	    // Handle authentication failure
//	}
//
// # Identity Extraction
//
// The adapter can extract identity from multiple certificate fields:
//
//   - IdentityFieldEmail: Email from SAN extension
//   - IdentityFieldCN: Common Name from Subject
//   - IdentityFieldSerialNumber: Serial Number from Subject
//   - IdentityFieldSubjectDN: Full Distinguished Name
//   - IdentityFieldOrganization: Organization from Subject
//
// # Integration with IAM
//
// The Identity struct returned by Authenticate is designed to be compatible
// with the IAM session system in pkg/webservice/v1/middleware/iam, allowing
// seamless integration between mTLS authentication and IAM authorization.
package auth
