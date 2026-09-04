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

package bmc

import "crypto/fips140"

// minFIPSHMACKeyBytes is the shortest HMAC key FIPS 140-3 permits: SP 800-131A
// requires at least 112 bits of keying material, and crypto/hmac.New enforces
// it by PANICKING rather than returning an error when GODEBUG=fips140=only is
// set. A panic inside a protocol handshake takes the daemon with it, so the
// length is checked before any key reaches hmac.New (#209).
const minFIPSHMACKeyBytes = 112 / 8

// rmcpValidateSessionSecret refuses an RMCP+ credential that cannot serve as an
// HMAC key under FIPS activation, before the RAKP exchange derives anything
// from it.
//
// Unlike this package's algorithm tables, which are selected by the `fips`
// BUILD TAG so that MD5 and SHA-1 are absent from the binary, this check is a
// RUNTIME one. That is deliberate and not an oversight: nothing needs removing
// from the binary here, and crypto/hmac's own enforcement is keyed on the
// GODEBUG setting, so a build-tag check would disagree with it in both
// directions. Doc 04 ruling 1 is explicit that one artifact serves both markets
// and FIPS activation is a deployment decision, so a binary built without the
// tag can still be run under fips140=only — and would still panic.
//
// Refusing here is what doc 04 ruling 7 requires of an interop surface under
// FIPS activation: restrict to approved options, or disable with a clear typed
// error. An IPMI password shorter than 14 bytes leaves the controller
// unreachable over RMCP+ in a FIPS deployment; Redfish over TLS is unaffected.
func rmcpValidateSessionSecret(password string, kg []byte) error {
	return rmcpValidateSessionSecretForMode(password, kg, fips140.Enabled())
}

// rmcpValidateSessionSecretForMode is the decision, with the mode passed in so
// it can be exercised in both states from a single test binary — GODEBUG is
// fixed before main runs and cannot be toggled from a test. It mirrors the
// ValidateKDFForMode convention in pkg/fips.
func rmcpValidateSessionSecretForMode(password string, kg []byte, fipsActive bool) error {
	if !fipsActive {
		return nil
	}

	// The KG key, when configured, is the SIK's HMAC key; otherwise the
	// password serves as KG. The password is always the RAKP2/RAKP3 auth-code
	// key, so it is checked either way.
	if len(password) < minFIPSHMACKeyBytes {
		return ErrFIPSKeyTooShort{Field: "password", Length: len(password), Minimum: minFIPSHMACKeyBytes}
	}
	if len(kg) > 0 && len(kg) < minFIPSHMACKeyBytes {
		return ErrFIPSKeyTooShort{Field: "KG key", Length: len(kg), Minimum: minFIPSHMACKeyBytes}
	}
	return nil
}
