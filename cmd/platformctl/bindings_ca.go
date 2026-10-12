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

package main

import (
	"encoding/base64"
	"log/slog"
	"strings"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	casvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ca"
)

// CABinding exposes Certificate Authority service methods to the Wails frontend.
type CABinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewCABinding creates a new CABinding.
func NewCABinding(logger *slog.Logger, conn *ConnectionBinding) *CABinding {
	return &CABinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *CABinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// GetCAInfo returns information about the Certificate Authority.
func (b *CABinding) GetCAInfo() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.CA().GetCAInfo(b.conn.ctx, &platformv1.GetCAInfoRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// IssueCertificate issues a new certificate with the given common name and key algorithm.
func (b *CABinding) IssueCertificate(commonName, algorithm string, validDays int32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	keyAlgo, err := parseKeyAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	resp, err := cl.CA().IssueCertificate(b.conn.ctx, &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject: &platformv1.Subject{
				CommonName: commonName,
			},
			KeyAlgorithm: keyAlgo,
			ValidDays:    validDays,
		},
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// SignCSR certifies, for code signing only, the KMS key that signed the PEM
// PKCS#10 request csrPEM: `platformctl ca sign-csr`, through the same SDK
// call. validDays zero selects the CA default. Only the platform admin may
// sign (docs/ca/api.md §4); anyone else gets the CA's PermissionDenied.
// The result is the object the CLI prints with --output json.
func (b *CABinding) SignCSR(csrPEM string, validDays int32) (*casvc.IssueCertificateResult, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	grpcClient := cl.CA()
	if grpcClient == nil {
		return nil, &ServiceUnavailableError{Service: "CA"}
	}

	result, err := casvc.NewClientFromGRPC(grpcClient).SignCSRDomain(b.conn.ctx, &casvc.SignCSRParams{
		CSRPEM:    csrPEM,
		ValidDays: validDays,
	})
	if err != nil {
		return nil, err
	}
	if result.Certificate == nil || len(result.Certificate.Pem) == 0 {
		return nil, &NoCertificateIssuedError{}
	}
	return result, nil
}

// GetCertificate retrieves a certificate by serial number.
func (b *CABinding) GetCertificate(serialNumber string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.CA().GetCertificate(b.conn.ctx, &platformv1.GetCertificateRequest{
		Serial:     serialNumber,
		IncludePem: true,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// ListCertificates returns a list of all certificates.
func (b *CABinding) ListCertificates() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.CA().ListCertificates(b.conn.ctx, &platformv1.ListCertificatesRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// RevokeCertificate revokes a certificate by serial number with the given reason.
func (b *CABinding) RevokeCertificate(serialNumber, reason string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	revReason, err := parseRevocationReason(reason)
	if err != nil {
		return nil, err
	}

	resp, err := cl.CA().RevokeCertificate(b.conn.ctx, &platformv1.RevokeCertificateRequest{
		Serial: serialNumber,
		Reason: revReason,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// RenewCertificate renews an existing certificate by serial number.
func (b *CABinding) RenewCertificate(serialNumber string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.CA().RenewCertificate(b.conn.ctx, &platformv1.RenewCertificateRequest{
		Serial:       serialNumber,
		PreserveSans: true,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// VerifyCertificate verifies a certificate provided as base64-encoded PEM.
func (b *CABinding) VerifyCertificate(certificatePemB64 string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	pemBytes, err := base64.StdEncoding.DecodeString(certificatePemB64)
	if err != nil {
		return nil, &InvalidInputError{Field: "certificatePem", Reason: "invalid base64 encoding"}
	}

	resp, err := cl.CA().VerifyCertificate(b.conn.ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem:   pemBytes,
		VerifyRevocation: true,
		VerifyExpiration: true,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetCRL returns the current Certificate Revocation List.
func (b *CABinding) GetCRL() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.CA().GetCRL(b.conn.ctx, &platformv1.GetCRLRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetCABundle returns the CA certificate bundle.
func (b *CABinding) GetCABundle() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.CA().GetCABundle(b.conn.ctx, &platformv1.GetCABundleRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// parseKeyAlgorithm converts a key algorithm string to the protobuf enum.
// It accepts both short names (e.g., "ecdsa_p256") and full enum names
// (e.g., "KEY_ALGORITHM_ECDSA_P256").
func parseKeyAlgorithm(input string) (platformv1.KeyAlgorithm, error) {
	upper := strings.ToUpper(input)

	if val, ok := platformv1.KeyAlgorithm_value[upper]; ok {
		return platformv1.KeyAlgorithm(val), nil
	}

	prefixed := "KEY_ALGORITHM_" + upper
	if val, ok := platformv1.KeyAlgorithm_value[prefixed]; ok {
		return platformv1.KeyAlgorithm(val), nil
	}

	return platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED,
		&InvalidInputError{Field: "algorithm", Reason: "unknown key algorithm: " + input}
}

// parseRevocationReason converts a revocation reason string to the protobuf enum.
// It accepts both short names (e.g., "key_compromise") and full enum names
// (e.g., "REVOCATION_REASON_KEY_COMPROMISE").
func parseRevocationReason(input string) (platformv1.RevocationReason, error) {
	upper := strings.ToUpper(input)

	if val, ok := platformv1.RevocationReason_value[upper]; ok {
		return platformv1.RevocationReason(val), nil
	}

	prefixed := "REVOCATION_REASON_" + upper
	if val, ok := platformv1.RevocationReason_value[prefixed]; ok {
		return platformv1.RevocationReason(val), nil
	}

	return platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED,
		&InvalidInputError{Field: "reason", Reason: "unknown revocation reason: " + input}
}
