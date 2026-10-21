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

package acme

import "fmt"

// ErrACMEDaemonCallMissing is returned by a verb whose input is valid but which
// platformd cannot serve: the platform SDK client has no ACME call on any
// transport, so the verb refuses rather than reaching the ACME server itself.
// Section names the RFC 8555 operation the missing daemon call would carry.
// This is an SDK gap (go-quicbaas), not a platform feature to build locally.
type ErrACMEDaemonCallMissing struct {
	Command string
	Section string
}

func (e ErrACMEDaemonCallMissing) Error() string {
	return fmt.Sprintf("acme %s: platformd has no ACME call for RFC 8555 %s (SDK gap)", e.Command, e.Section)
}

// ErrMissingEmail is returned when register is run without --email
type ErrMissingEmail struct{}

func (e ErrMissingEmail) Error() string {
	return "account email is required; specify --email"
}

// ErrInvalidEmail is returned when --email is not a bare RFC 5322 address
type ErrInvalidEmail struct {
	Email string
}

func (e ErrInvalidEmail) Error() string {
	return fmt.Sprintf("invalid account email %q: expected a bare address such as admin@example.com", e.Email)
}

// ErrInvalidAuthorizationType is returned when --authz names an unknown type
type ErrInvalidAuthorizationType struct {
	Type string
}

func (e ErrInvalidAuthorizationType) Error() string {
	return fmt.Sprintf("invalid authorization type %q: expected dns, ip or permanent-identifier", e.Type)
}

// ErrInvalidChallengeType is returned when --challenge names an unknown type
type ErrInvalidChallengeType struct {
	Type string
}

func (e ErrInvalidChallengeType) Error() string {
	return fmt.Sprintf("invalid challenge type %q: expected http-01, dns-01, endorse-01, device-01 or device-attest-01", e.Type)
}

// ErrInvalidCertificateURL is returned when the download URL is not an
// absolute https URL
type ErrInvalidCertificateURL struct {
	URL string
}

func (e ErrInvalidCertificateURL) Error() string {
	return fmt.Sprintf("invalid certificate URL %q: expected an absolute https URL", e.URL)
}

// ErrRegisterAccountFailed is returned when ACME account registration fails
type ErrRegisterAccountFailed struct {
	Reason string
}

func (e ErrRegisterAccountFailed) Error() string {
	return fmt.Sprintf("failed to register ACME account: %s", e.Reason)
}

// ErrRenewCertificateFailed is returned when certificate renewal fails
type ErrRenewCertificateFailed struct {
	Reason string
}

func (e ErrRenewCertificateFailed) Error() string {
	return fmt.Sprintf("failed to renew certificate: %s", e.Reason)
}

// ErrDownloadCertificateFailed is returned when certificate download fails
type ErrDownloadCertificateFailed struct {
	Reason string
}

func (e ErrDownloadCertificateFailed) Error() string {
	return fmt.Sprintf("failed to download certificate: %s", e.Reason)
}

// ErrRotateKeyFailed is returned when account key rotation fails
type ErrRotateKeyFailed struct {
	Reason string
}

func (e ErrRotateKeyFailed) Error() string {
	return fmt.Sprintf("failed to rotate account key: %s", e.Reason)
}

// ErrMissingCertificateURL is returned when certificate URL is not provided
type ErrMissingCertificateURL struct{}

func (e ErrMissingCertificateURL) Error() string {
	return "certificate URL is required"
}

// ErrMissingAuthorizationValue is returned when authorization value cannot be determined
type ErrMissingAuthorizationValue struct{}

func (e ErrMissingAuthorizationValue) Error() string {
	return "could not determine authorization value; specify --cn or --sans-dns/--sans-ip"
}

// ErrIPAuthorizationRequiresIP is returned when IP authorization is used without IP SANs
type ErrIPAuthorizationRequiresIP struct{}

func (e ErrIPAuthorizationRequiresIP) Error() string {
	return "IP authorization requires --sans-ip"
}

// ErrMissingSubjectField is returned when a required subject field is missing
type ErrMissingSubjectField struct {
	Field string
}

func (e ErrMissingSubjectField) Error() string {
	return fmt.Sprintf("missing required subject field: %s", e.Field)
}
