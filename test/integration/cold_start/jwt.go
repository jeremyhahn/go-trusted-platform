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

//go:build integration

package cold_start

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// decodeJWTSubClaim returns the "sub" claim from the supplied JWT
// without performing signature verification. The cold-start scenario
// trusts the daemon end-to-end, so the test only needs to confirm that
// a freshly issued token names the expected subject.
func decodeJWTSubClaim(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", &ErrJWTDecode{Reason: "expected 3 dot-separated segments"}
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", &ErrJWTDecode{Reason: "decode payload: " + err.Error()}
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		return "", &ErrJWTDecode{Reason: "unmarshal payload: " + err.Error()}
	}
	if claims.Sub == "" {
		return "", &ErrJWTDecode{Reason: "sub claim missing"}
	}
	return claims.Sub, nil
}
