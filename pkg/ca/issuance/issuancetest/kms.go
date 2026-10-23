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

package issuancetest

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"testing"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// ErrKeyNotFound is what KMS answers for a key it does not hold.
var ErrKeyNotFound = errors.New("issuancetest: key not found")

// KMS answers public-key lookups from Keys, as the platform KMS does: the
// public key is PKIX DER.
type KMS struct {
	Keys map[string][]byte
}

// NewKMS returns a KMS holding public under keyID.
func NewKMS(t testing.TB, keyID string, public crypto.PublicKey) *KMS {
	t.Helper()
	k := &KMS{Keys: map[string][]byte{}}
	k.Add(t, keyID, public)
	return k
}

// Add makes the KMS hold public under keyID.
func (k *KMS) Add(t testing.TB, keyID string, public crypto.PublicKey) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatalf("issuancetest KMS key: %v", err)
	}
	k.Keys[keyID] = der
}

// GetPublicKey returns the public key held under req.KeyID.
func (k *KMS) GetPublicKey(_ context.Context, req *baasservice.GetPublicKeyRequest) (*baasservice.GetPublicKeyResponse, error) {
	der, ok := k.Keys[req.KeyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return &baasservice.GetPublicKeyResponse{KeyID: req.KeyID, PublicKey: der}, nil
}
