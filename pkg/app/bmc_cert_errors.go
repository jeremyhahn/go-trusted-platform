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

package app

import (
	"errors"
	"fmt"
)

// ErrBMCCertDisabled indicates bmcCfg.Certificate is nil — TLS
// management is not configured for the device.
var ErrBMCCertDisabled = errors.New("app: BMC TLS management disabled (Certificate unset)")

// ErrMissingACMEConfig indicates ACME issuance was requested but
// bmcCfg.Certificate.ACME (flat fields) is absent.
var ErrMissingACMEConfig = errors.New("app: BMC certificate ACME request config missing")

// ErrMissingAuthzValue indicates ACME issuance cannot proceed because
// neither ACME.AuthzValue nor Subject.CommonName is set.
var ErrMissingAuthzValue = errors.New("app: BMC certificate missing AuthzValue/CommonName")

// ErrMissingLocalCAIssuer indicates the local CA issuer dependency
// was nil but is required for fallback issuance.
var ErrMissingLocalCAIssuer = errors.New("app: local CA issuer required for BMC cert issuance")

// ErrInvalidChallengeType indicates the configured ACME challenge
// type is not "dns-01". Defense in depth; P2 config validation
// should reject this at load.
type ErrInvalidChallengeType struct {
	Got string
}

func (e ErrInvalidChallengeType) Error() string {
	return fmt.Sprintf("app: BMC cert requires challenge_type=dns-01, got %q", e.Got)
}

// ErrUnsupportedKeyAlgorithm indicates the configured key algorithm
// is not supported for BMC cert keypair generation.
type ErrUnsupportedKeyAlgorithm struct {
	Algorithm string
}

func (e ErrUnsupportedKeyAlgorithm) Error() string {
	return fmt.Sprintf("app: unsupported BMC key algorithm %q (supported: ECDSA, RSA)", e.Algorithm)
}

// ErrUnsupportedKeyCurve indicates the configured ECDSA curve is not
// supported.
type ErrUnsupportedKeyCurve struct {
	Curve string
}

func (e ErrUnsupportedKeyCurve) Error() string {
	return fmt.Sprintf("app: unsupported ECDSA curve %q (supported: P-256, P-384, P-521)", e.Curve)
}

// ErrKeyGenerate wraps a failure in key-pair generation.
type ErrKeyGenerate struct {
	Cause error
}

func (e ErrKeyGenerate) Error() string {
	return fmt.Sprintf("app: BMC key generation failed: %v", e.Cause)
}

func (e ErrKeyGenerate) Unwrap() error { return e.Cause }

// ErrCSRCreate wraps a failure building the BMC CSR.
type ErrCSRCreate struct {
	Cause error
}

func (e ErrCSRCreate) Error() string {
	return fmt.Sprintf("app: BMC CSR creation failed: %v", e.Cause)
}

func (e ErrCSRCreate) Unwrap() error { return e.Cause }

// ErrMissingDNSUpdater reports that dns-01 was requested without a DNS updater
// to answer the challenge with.
//
// A typed error rather than a nil dereference: the challenge callbacks run
// inside the ACME client, so the panic would land on whichever goroutine drove
// issuance -- during boot that is platformd's own, outside the renewal sweep's
// panic isolation.
type ErrMissingDNSUpdater struct {
	AuthzValue string
}

func (e ErrMissingDNSUpdater) Error() string {
	return fmt.Sprintf("app: dns-01 challenge for %q requires a DNS updater; none "+
		"is configured, so the certificate cannot be issued", e.AuthzValue)
}

// ErrBMCACMEIssuerUnavailable reports that the BMC declares ACME issuance but
// no ACME issuer was wired, and the caller required ACME.
//
// Returned instead of falling back to the local CA: a validated BMC cert config
// always asked for ACME dns-01, so substituting a different issuer changes who
// the BMC's certificate is trusted by. The only other evidence would be the
// issuer field of a certificate nobody inspects until it fails a trust check.
type ErrBMCACMEIssuerUnavailable struct {
	DeviceID string
}

func (e ErrBMCACMEIssuerUnavailable) Error() string {
	return fmt.Sprintf("app: BMC %s is configured for ACME issuance but no ACME "+
		"issuer is available; refusing to substitute the local CA", e.DeviceID)
}

// ErrBMCACMEIssuance wraps an ACME-path issuance failure.
type ErrBMCACMEIssuance struct {
	DeviceID string
	Cause    error
}

func (e ErrBMCACMEIssuance) Error() string {
	return fmt.Sprintf("app: BMC %s ACME issuance failed: %v", e.DeviceID, e.Cause)
}

func (e ErrBMCACMEIssuance) Unwrap() error { return e.Cause }

// ErrBMCLocalIssuance wraps a local-CA-path issuance failure.
type ErrBMCLocalIssuance struct {
	DeviceID string
	Cause    error
}

func (e ErrBMCLocalIssuance) Error() string {
	return fmt.Sprintf("app: BMC %s local CA issuance failed: %v", e.DeviceID, e.Cause)
}

func (e ErrBMCLocalIssuance) Unwrap() error { return e.Cause }

// ErrBMCDeploy wraps a failure pushing the issued cert to the BMC.
type ErrBMCDeploy struct {
	DeviceID string
	Cause    error
}

func (e ErrBMCDeploy) Error() string {
	return fmt.Sprintf("app: BMC %s cert deploy failed: %v", e.DeviceID, e.Cause)
}

func (e ErrBMCDeploy) Unwrap() error { return e.Cause }
