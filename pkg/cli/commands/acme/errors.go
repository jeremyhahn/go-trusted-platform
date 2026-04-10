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

// ErrDaemonConnectionRequired is returned when a command requires daemon connection
type ErrDaemonConnectionRequired struct {
	Command string
}

func (e ErrDaemonConnectionRequired) Error() string {
	return fmt.Sprintf("daemon connection required for %s command", e.Command)
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
