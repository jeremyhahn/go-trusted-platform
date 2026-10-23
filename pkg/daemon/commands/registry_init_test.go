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

package commands

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/registry"
)

var errRegistryTestKeyNotFound = errors.New("kms: key not found")

// registryTestSDK is an SDK client whose Security().KMS() and
// Security().Crypto() hold one real ECDSA key. Only the calls the registry
// signer makes are implemented; any other call panics on the nil embedded
// interface.
type registryTestSDK struct {
	quicbaassdk.Client
	security *registryTestSecurity
}

func (c *registryTestSDK) Security() quicbaassdk.SecurityService { return c.security }

type registryTestSecurity struct {
	quicbaassdk.SecurityService
	kms    *registryTestKMS
	crypto *registryTestCrypto
}

func (s *registryTestSecurity) KMS() quicbaassdk.KMSClient       { return s.kms }
func (s *registryTestSecurity) Crypto() quicbaassdk.CryptoClient { return s.crypto }

type registryTestKMS struct {
	kms.Client
	keyID string
}

func (k *registryTestKMS) GetKey(_ context.Context, keyID string) (*kms.KeyInfo, error) {
	if keyID != k.keyID {
		return nil, errRegistryTestKeyNotFound
	}
	return &kms.KeyInfo{KeyID: keyID, Algorithm: kms.AlgorithmECDSAP256}, nil
}

type registryTestCrypto struct {
	quicbaassdk.CryptoClient
	priv *ecdsa.PrivateKey
}

func (c *registryTestCrypto) Sign(_ context.Context, req *quicbaassdk.SignRequest) (*quicbaassdk.SignResponse, error) {
	sig, err := ecdsa.SignASN1(rand.Reader, c.priv, req.Data)
	if err != nil {
		return nil, err
	}
	return &quicbaassdk.SignResponse{Signature: sig}, nil
}

func newRegistryTestSDK(t *testing.T, keyID string) *registryTestSDK {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return &registryTestSDK{security: &registryTestSecurity{
		kms:    &registryTestKMS{keyID: keyID},
		crypto: &registryTestCrypto{priv: priv},
	}}
}

func registryTestImage() *registry.Image {
	const layerType = "application/vnd.oci.image.layer.v1.tar"
	content := []byte("layer")
	sum := sha256.Sum256(content)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	return &registry.Image{
		Manifest: &registry.ImageManifest{
			SchemaVersion: 2,
			MediaType:     "application/vnd.oci.image.manifest.v1+json",
			Layers:        []registry.Descriptor{{MediaType: layerType, Digest: digest, Size: int64(len(content))}},
		},
		Layers: []registry.Layer{{Digest: digest, MediaType: layerType, Size: int64(len(content)), Content: content}},
	}
}

func TestRegistryManifestSigner_SignsWithTheSDKKey(t *testing.T) {
	sdk := newRegistryTestSDK(t, "web-sign")
	signer, err := registryManifestSigner(sdk)
	if err != nil || signer == nil {
		t.Fatalf("registryManifestSigner = (%v, %v), want a signer", signer, err)
	}
	digest := sha256.Sum256([]byte("manifest"))
	sig, alg, err := signer.Sign(context.Background(), "web-sign", digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if alg != registry.SignatureAlgorithmECDSAP256SHA256 {
		t.Errorf("algorithm = %q, want %q", alg, registry.SignatureAlgorithmECDSAP256SHA256)
	}
	if !ecdsa.VerifyASN1(&sdk.security.crypto.priv.PublicKey, digest[:], sig) {
		t.Fatal("the signature does not verify under the SDK KMS key")
	}
	_, _, err = signer.Sign(context.Background(), "no-such-key", digest[:])
	if !errors.As(err, &registry.ErrSigningKeyUnavailable{}) {
		t.Fatalf("Sign with a missing key = %v, want ErrSigningKeyUnavailable", err)
	}
}

func TestRegistryManifestSigner_NoSDKClientGivesNoSigner(t *testing.T) {
	signer, err := registryManifestSigner(nil)
	if err != nil || signer != nil {
		t.Fatalf("registryManifestSigner(nil) = (%v, %v), want no signer and no error", signer, err)
	}
}

// Without an SDK client the daemon wires no signer: a signed push is
// refused with ErrSigningNotConfigured rather than signed with local keys.
func TestInitRegistryService_NoSDKClientRefusesSignedPush(t *testing.T) {
	cfg := &daemon.Config{}
	initRegistryServiceOnConfig(newTestLogger(), &app.App{PlatformDir: t.TempDir()}, cfg)
	t.Cleanup(func() { delete(registryBackends, cfg) })

	reg, ok := registryBackends[cfg].(*registry.Registry)
	if !ok || cfg.RegistryService == nil {
		t.Fatalf("registry not wired: backend %T", registryBackends[cfg])
	}
	err := reg.Push(context.Background(), "apps/web:v1", registryTestImage(), registry.PushOptions{SignImage: true})
	if !errors.As(err, &registry.ErrSigningNotConfigured{}) {
		t.Fatalf("signed Push = %v, want ErrSigningNotConfigured", err)
	}
	if err := reg.Push(context.Background(), "apps/web:v1", registryTestImage(), registry.PushOptions{}); err != nil {
		t.Fatalf("unsigned Push: %v", err)
	}
}
