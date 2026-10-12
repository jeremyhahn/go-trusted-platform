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

package service

import "regexp"

// iamEmailPattern is the address rule the QuicBaaS IAM identity store applies
// to every user the platform mirrors into it (go-quicbaas pkg/iam
// validateEmail). The SDK does not export that validator, so the platform
// holds this one copy and every edge that accepts an address the platform
// will mirror — WebAuthn registration and invitations — validates against it.
// An address IAM would reject is then refused before anything is derived from
// it, rather than after a user and tenant already exist (#643).
var iamEmailPattern = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// ValidateEmail reports whether email is an address the IAM identity store
// accepts. It returns ErrInvalidEmail when it is not.
func ValidateEmail(email string) error {
	if !iamEmailPattern.MatchString(email) {
		return ErrInvalidEmail{Email: email}
	}
	return nil
}
