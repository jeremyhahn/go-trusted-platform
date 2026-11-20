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

package kms

import (
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// TestRESTAdapterGenerateKeyBodyKeySpec checks that the body the REST
// adapter sends for key generation carries key_spec.algorithm, the field
// the daemon's handler requires (docs/kms/api.md).
func TestRESTAdapterGenerateKeyBodyKeySpec(t *testing.T) {
	r := &RESTAdapter{}
	for _, alg := range []string{"AES-128-GCM", "AES-256-GCM", "RSA-2048", "ECDSA-P256"} {
		t.Run(alg, func(t *testing.T) {
			req := &service.GenerateKeyRequest{
				Name:          "keyspec-" + alg,
				KeyAttributes: r.algorithmStringToKeyAttributes(alg),
				Usage:         r.purposeToKeyUsage("encrypt"),
			}
			body, err := json.Marshal(r.convertToGenerateKeyRequest(req))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var wire struct {
				KeySpec *struct {
					Algorithm string `json:"algorithm"`
				} `json:"key_spec"`
			}
			if err := json.Unmarshal(body, &wire); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if wire.KeySpec == nil {
				t.Fatalf("body has no key_spec object: %s", body)
			}
			if wire.KeySpec.Algorithm != alg {
				t.Fatalf("key_spec.algorithm = %q, want %q: %s", wire.KeySpec.Algorithm, alg, body)
			}
		})
	}
}
