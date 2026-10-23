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

package issuance

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
)

// fakeKMSClient answers GetPublicKey from keys; the rest of the client is
// never called.
type fakeKMSClient struct {
	kmsclient.Client
	keys map[string][]byte
}

var errNoKey = errors.New("public key not found")

func (c fakeKMSClient) GetPublicKey(ctx context.Context, keyID string) (*kmsclient.GetPublicKeyResponse, error) {
	der, ok := c.keys[keyID]
	if !ok {
		return nil, errNoKey
	}
	return &kmsclient.GetPublicKeyResponse{KeyID: keyID, PublicKey: der}, nil
}

func TestClientKMS_CertifiesTheClientsKey(t *testing.T) {
	key := issuancetest.RSAKey(t)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ca := issuancetest.NewCA(t)
	kms := ClientKMS(fakeKMSClient{keys: map[string][]byte{"rpi/fleet": der}})

	cert, err := SignCSR(context.Background(), ca, kms, &CSR{PEM: issuancetest.CSR(t, key, "rpi/fleet")})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("the certificate does not certify the client's key")
	}
}

func TestClientKMS_KeyTheClientLacks(t *testing.T) {
	key := issuancetest.RSAKey(t)
	kms := ClientKMS(fakeKMSClient{keys: map[string][]byte{}})

	_, err := SignCSR(context.Background(), issuancetest.NewCA(t), kms, &CSR{PEM: issuancetest.CSR(t, key, "rpi/fleet")})
	var keyErr *CSRKeyError
	if !errors.As(err, &keyErr) || !errors.Is(err, errNoKey) {
		t.Fatalf("SignCSR = %v, want CSRKeyError wrapping the client's error", err)
	}
}

func TestClientKMS_NoClientFailsClosed(t *testing.T) {
	if kms := ClientKMS(nil); kms != nil {
		t.Fatalf("ClientKMS(nil) = %v, want nil", kms)
	}
}
