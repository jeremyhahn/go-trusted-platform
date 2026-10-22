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

package registry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
)

var (
	errFakeKeyNotFound = errors.New("kms: key not found")
	errFakeSDKDown     = errors.New("kms: backend unavailable")
)

// fakeSDKKey is one key the fake SDK KMS holds. priv is nil for keys the
// fake cannot sign with (RSA, AES): the signer must refuse those before it
// reaches Sign.
type fakeSDKKey struct {
	info kms.KeyInfo
	priv *ecdsa.PrivateKey
}

// fakeSDKKMS is an in-process stand-in for Security().KMS() and
// Security().Crypto(): it holds real ECDSA keys and signs with them, and it
// records every key creation and sign request so a test can prove the
// signer used the named key and created none.
type fakeSDKKMS struct {
	keys      map[string]*fakeSDKKey
	signErr   error
	emptySig  bool
	generated int
	signReqs  []quicbaas.SignRequest
}

func newFakeSDKKMS() *fakeSDKKMS {
	return &fakeSDKKMS{keys: map[string]*fakeSDKKey{}}
}

func (f *fakeSDKKMS) addECDSAKey(t *testing.T, keyID string, curve elliptic.Curve, alg kms.KeyAlgorithm) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	f.keys[keyID] = &fakeSDKKey{info: kms.KeyInfo{KeyID: keyID, Algorithm: alg}, priv: priv}
}

func (f *fakeSDKKMS) addKey(keyID string, alg kms.KeyAlgorithm) {
	f.keys[keyID] = &fakeSDKKey{info: kms.KeyInfo{KeyID: keyID, Algorithm: alg}}
}

func (f *fakeSDKKMS) publicKey(t *testing.T, keyID string) *ecdsa.PublicKey {
	t.Helper()
	key, ok := f.keys[keyID]
	if !ok || key.priv == nil {
		t.Fatalf("fake KMS has no ECDSA key %q", keyID)
	}
	return &key.priv.PublicKey
}

func (f *fakeSDKKMS) GetKey(_ context.Context, keyID string) (*kms.KeyInfo, error) {
	key, ok := f.keys[keyID]
	if !ok {
		return nil, errFakeKeyNotFound
	}
	info := key.info
	return &info, nil
}

// GenerateKey is the KMS creation call. The signer must never reach it; the
// counter proves it did not.
func (f *fakeSDKKMS) GenerateKey(_ context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
	f.generated++
	return &kms.GenerateKeyResponse{KeyID: req.Name}, nil
}

func (f *fakeSDKKMS) Sign(_ context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error) {
	f.signReqs = append(f.signReqs, *req)
	if f.signErr != nil {
		return nil, f.signErr
	}
	if f.emptySig {
		return &quicbaas.SignResponse{}, nil
	}
	key, ok := f.keys[req.KeyID]
	if !ok || key.priv == nil {
		return nil, errFakeKeyNotFound
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key.priv, req.Data)
	if err != nil {
		return nil, err
	}
	return &quicbaas.SignResponse{Signature: sig, KeyVersion: 1}, nil
}

func newTestSDKSigner(t *testing.T, fake *fakeSDKKMS) *SDKSigner {
	t.Helper()
	signer, err := NewSDKSigner(fake, fake)
	if err != nil {
		t.Fatalf("NewSDKSigner: %v", err)
	}
	return signer
}

func signTestDigest(msg string) []byte {
	sum := sha256.Sum256([]byte(msg))
	return sum[:]
}

func TestSDKSigner_SignsWithTheNamedKey(t *testing.T) {
	fake := newFakeSDKKMS()
	fake.addECDSAKey(t, "key-a", elliptic.P256(), kms.AlgorithmECDSAP256)
	fake.addECDSAKey(t, "key-b", elliptic.P256(), kms.AlgorithmECDSAP256)
	fake.addECDSAKey(t, "key-384", elliptic.P384(), kms.AlgorithmECDSAP384)
	signer := newTestSDKSigner(t, fake)
	digest := signTestDigest("manifest")

	sig, alg, err := signer.Sign(context.Background(), "key-a", digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if alg != SignatureAlgorithmECDSAP256SHA256 {
		t.Errorf("algorithm = %q, want %q", alg, SignatureAlgorithmECDSAP256SHA256)
	}
	if !ecdsa.VerifyASN1(fake.publicKey(t, "key-a"), digest, sig) {
		t.Fatal("the signature does not verify under the named key")
	}
	if ecdsa.VerifyASN1(fake.publicKey(t, "key-b"), digest, sig) {
		t.Fatal("the signature verifies under a key the push did not name")
	}
	want := quicbaas.SignRequest{KeyID: "key-a", Data: digest, HashAlg: quicbaas.HashSHA256, PreHashed: true}
	got := fake.signReqs[0]
	if got.KeyID != want.KeyID || got.HashAlg != want.HashAlg || got.PreHashed != want.PreHashed || string(got.Data) != string(want.Data) {
		t.Errorf("SDK sign request = %+v, want %+v", got, want)
	}

	sig, alg, err = signer.Sign(context.Background(), "key-384", digest)
	if err != nil {
		t.Fatalf("Sign P-384: %v", err)
	}
	if alg != SignatureAlgorithmECDSAP384SHA256 || !ecdsa.VerifyASN1(fake.publicKey(t, "key-384"), digest, sig) {
		t.Errorf("P-384 sign = (%q, verifies=false), want %q and a verifying signature", alg, SignatureAlgorithmECDSAP384SHA256)
	}
	if fake.generated != 0 {
		t.Errorf("signer created %d keys, want none", fake.generated)
	}
}

func TestSDKSigner_MissingKeyIsUnavailableAndNotCreated(t *testing.T) {
	fake := newFakeSDKKMS()
	signer := newTestSDKSigner(t, fake)

	_, _, err := signer.Sign(context.Background(), "registry-default", signTestDigest("manifest"))
	var unavailable ErrSigningKeyUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("Sign error = %v, want ErrSigningKeyUnavailable", err)
	}
	if unavailable.KeyID != "registry-default" || !errors.Is(err, errFakeKeyNotFound) {
		t.Errorf("ErrSigningKeyUnavailable = %+v, want key registry-default wrapping the KMS error", unavailable)
	}
	if fake.generated != 0 || len(fake.keys) != 0 {
		t.Errorf("signer created a key: generated=%d keys=%d", fake.generated, len(fake.keys))
	}
	if len(fake.signReqs) != 0 {
		t.Errorf("signer reached Sign %d times for a missing key", len(fake.signReqs))
	}
}

func TestSDKSigner_RefusesKeysThatCannotSignManifests(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  kms.KeyAlgorithm
	}{
		{name: "RSA", alg: kms.AlgorithmRSA2048},
		{name: "AES", alg: kms.AlgorithmAES256GCM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeSDKKMS()
			fake.addKey("wrong-kind", tc.alg)
			signer := newTestSDKSigner(t, fake)

			_, _, err := signer.Sign(context.Background(), "wrong-kind", signTestDigest("manifest"))
			var unsupported ErrSigningKeyUnsupported
			if !errors.As(err, &unsupported) || unsupported.KeyID != "wrong-kind" {
				t.Fatalf("Sign error = %v, want ErrSigningKeyUnsupported for wrong-kind", err)
			}
			if len(fake.signReqs) != 0 {
				t.Error("signer asked the SDK to sign with an unsupported key")
			}
		})
	}
}

func TestSDKSigner_RejectsBadInput(t *testing.T) {
	fake := newFakeSDKKMS()
	fake.addECDSAKey(t, "k", elliptic.P256(), kms.AlgorithmECDSAP256)
	signer := newTestSDKSigner(t, fake)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	for _, tc := range []struct {
		name   string
		keyID  string
		digest []byte
	}{
		{name: "empty key ID", keyID: "", digest: signTestDigest("m")},
		{name: "short digest", keyID: "k", digest: []byte("short")},
		{name: "nil digest", keyID: "k", digest: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := signer.Sign(context.Background(), tc.keyID, tc.digest)
			if !errors.As(err, &ErrInvalidSigningRequest{}) {
				t.Fatalf("Sign error = %v, want ErrInvalidSigningRequest", err)
			}
		})
	}
	t.Run("cancelled context", func(t *testing.T) {
		if _, _, err := signer.Sign(cancelled, "k", signTestDigest("m")); !errors.Is(err, context.Canceled) {
			t.Fatalf("Sign error = %v, want context.Canceled", err)
		}
	})
	if len(fake.signReqs) != 0 {
		t.Errorf("signer reached the SDK %d times on bad input", len(fake.signReqs))
	}
}

func TestNewSDKSigner_RequiresBothClients(t *testing.T) {
	fake := newFakeSDKKMS()
	for _, tc := range []struct {
		name   string
		keys   SDKKeyReader
		crypto SDKSignClient
	}{
		{name: "nil KMS", keys: nil, crypto: fake},
		{name: "nil crypto", keys: fake, crypto: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := NewSDKSigner(tc.keys, tc.crypto)
			if !errors.As(err, &ErrSigningClientRequired{}) || signer != nil {
				t.Fatalf("NewSDKSigner = (%v, %v), want ErrSigningClientRequired", signer, err)
			}
		})
	}
}

func TestSDKSigner_SDKSignFailureIsTyped(t *testing.T) {
	t.Run("sign error", func(t *testing.T) {
		fake := newFakeSDKKMS()
		fake.addECDSAKey(t, "k", elliptic.P256(), kms.AlgorithmECDSAP256)
		fake.signErr = errFakeSDKDown
		_, _, err := newTestSDKSigner(t, fake).Sign(context.Background(), "k", signTestDigest("m"))
		var wrapped *WrappedError
		if !errors.As(err, &wrapped) || !errors.Is(err, errFakeSDKDown) {
			t.Fatalf("Sign error = %v, want *WrappedError wrapping the SDK error", err)
		}
	})
	t.Run("empty signature", func(t *testing.T) {
		fake := newFakeSDKKMS()
		fake.addECDSAKey(t, "k", elliptic.P256(), kms.AlgorithmECDSAP256)
		fake.emptySig = true
		_, _, err := newTestSDKSigner(t, fake).Sign(context.Background(), "k", signTestDigest("m"))
		var msg *MessageError
		if !errors.As(err, &msg) {
			t.Fatalf("Sign error = %v, want *MessageError for an empty SDK signature", err)
		}
	})
}
