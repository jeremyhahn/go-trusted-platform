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

package auth

import "errors"

var (
	ErrAuthenticationFailed = errors.New("platform: authentication failed")
	ErrInvalidOTPLength     = errors.New("platform: OTP must be at least 32 characters")
)

type PlatformAuthenticator interface {
	Authenticate(password []byte) error

	// Prompt reads the authenticator's secret from the terminal. It
	// returns an error rather than terminating the process so a caller
	// that can recover from a closed or non-interactive stdin does.
	Prompt() ([]byte, error)

	Provision(cn string, password, caPassword []byte) error
}
