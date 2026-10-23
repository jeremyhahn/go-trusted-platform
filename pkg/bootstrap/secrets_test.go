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

package bootstrap

import "testing"

func TestIsSecretURI_AcceptsEveryResolvedScheme(t *testing.T) {
	for _, uri := range []string{
		"kms://platform/so-pin",
		"remote-kms://kms.example.com/key",
		"env://BMC_PASSWORD",
		"idevid://ciphertext",
		"file:///run/secrets/switch",
		"dynamic://role",
		"xkms://backend/key",
		"credential://bmc/password",
		"autogen://platform/user-pin",
	} {
		if !IsSecretURI(uri) {
			t.Errorf("IsSecretURI(%q) = false, want true", uri)
		}
	}
}

func TestIsSecretURI_RejectsLiterals(t *testing.T) {
	for _, value := range []string{"", "hunter2", "12345678", "kms:/missing-slash", "vault://unknown", " kms://leading-space"} {
		if IsSecretURI(value) {
			t.Errorf("IsSecretURI(%q) = true, want false", value)
		}
	}
}
