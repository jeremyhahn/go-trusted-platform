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

package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicbaascrypto "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	caquicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/ca/quicbaas"
)

// issuedKeyKMS is a KMS that makes a real key for the algorithm it is asked
// for, so the key a certificate carries is the key the KMS issued.
type issuedKeyKMS struct {
	kms.Client
	keys        map[string][]byte
	generations int
}

func (k *issuedKeyKMS) GenerateKey(_ context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
	k.generations++
	var pub crypto.PublicKey
	switch req.Algorithm {
	case kms.AlgorithmRSA2048, kms.AlgorithmRSA4096:
		bits := 2048
		if req.Algorithm == kms.AlgorithmRSA4096 {
			bits = 4096
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		pub = &key.PublicKey
	case kms.AlgorithmECDSAP256, kms.AlgorithmECDSAP384:
		curve := elliptic.P256()
		if req.Algorithm == kms.AlgorithmECDSAP384 {
			curve = elliptic.P384()
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		pub = &key.PublicKey
	case kms.AlgorithmED25519:
		edPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		pub = edPub
	default:
		return nil, fmt.Errorf("issuedKeyKMS: unsupported algorithm %v", req.Algorithm)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	k.keys[req.Name] = der
	return &kms.GenerateKeyResponse{KeyID: req.Name, Algorithm: req.Algorithm, Version: 1}, nil
}

func (k *issuedKeyKMS) GetPublicKey(_ context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
	der, ok := k.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("issuedKeyKMS: no key %q", keyID)
	}
	return &kms.GetPublicKeyResponse{KeyID: keyID, PublicKey: der}, nil
}

// unusedCrypto satisfies the key store's crypto client; issuance here signs
// nothing with the issued key.
type unusedCrypto struct {
	quicbaascrypto.Client
}

// The REST issuance issues exactly the key size or curve the request names,
// through the real CA key store, or refuses the request before issuance when
// the key store cannot issue it exactly.
func TestIssueCertificate_IssuedKey(t *testing.T) {
	issuer := issuancetest.NewCA(t)

	tests := []struct {
		name         string
		keyAlgorithm string
		wantRSABits  int
		wantCurve    string
		wantEd25519  bool
		wantRefused  bool
	}{
		{name: "unspecified", wantCurve: "P-256"},
		{name: "RSA 2048", keyAlgorithm: "KEY_ALGORITHM_RSA_2048", wantRSABits: 2048},
		{name: "RSA 3072", keyAlgorithm: "KEY_ALGORITHM_RSA_3072", wantRefused: true},
		{name: "RSA 4096", keyAlgorithm: "KEY_ALGORITHM_RSA_4096", wantRSABits: 4096},
		{name: "ECDSA P-256", keyAlgorithm: "KEY_ALGORITHM_ECDSA_P256", wantCurve: "P-256"},
		{name: "ECDSA P-384", keyAlgorithm: "KEY_ALGORITHM_ECDSA_P384", wantCurve: "P-384"},
		{name: "ECDSA P-521", keyAlgorithm: "KEY_ALGORITHM_ECDSA_P521", wantRefused: true},
		{name: "Ed25519", keyAlgorithm: "KEY_ALGORITHM_ED25519", wantEd25519: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeKMS := &issuedKeyKMS{keys: map[string][]byte{}}
			keyStore, err := caquicbaas.NewQuicBaaSKeyStore(&caquicbaas.QuicBaaSKeyStoreConfig{
				KMS:    fakeKMS,
				Crypto: unusedCrypto{},
			})
			require.NoError(t, err)

			asked := false
			mockCA := &mockCertificateAuthority{
				initialized: true,
				issueCertificateFn: func(ctx context.Context, request *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
					asked = true
					attrs := request.KeyAttributes
					var key crypto.PrivateKey
					var genErr error
					switch attrs.KeyAlgorithm {
					case x509.RSA:
						key, genErr = keyStore.GenerateRSA(ctx, attrs)
					case x509.ECDSA:
						key, genErr = keyStore.GenerateECDSA(ctx, attrs)
					case x509.Ed25519:
						key, genErr = keyStore.GenerateEd25519(ctx, attrs)
					default:
						return nil, fmt.Errorf("unexpected key algorithm %v", attrs.KeyAlgorithm)
					}
					if genErr != nil {
						return nil, genErr
					}
					pub := key.(crypto.Signer).Public()
					tmpl := &x509.Certificate{
						SerialNumber: big.NewInt(2),
						Subject:      pkix.Name{CommonName: request.Subject.CommonName},
						NotBefore:    time.Now().Add(-time.Minute),
						NotAfter:     time.Now().Add(time.Hour),
					}
					der, certErr := x509.CreateCertificate(rand.Reader, tmpl, issuer.Root, pub, issuer.Key)
					if certErr != nil {
						return nil, certErr
					}
					cert, certErr := x509.ParseCertificate(der)
					if certErr != nil {
						return nil, certErr
					}
					return &xkmsca.IssuedCertificate{Certificate: cert}, nil
				},
			}
			router := newTestRouter(NewCARouter(newTestLogger(), mockCA, &mockHttpWriter{}))

			keyAlgorithm := ""
			if tt.keyAlgorithm != "" {
				keyAlgorithm = `"keyAlgorithm":"` + tt.keyAlgorithm + `",`
			}
			body := []byte(`{"request":{"subject":{"commonName":"issued.example.com"},` +
				keyAlgorithm + `"validDays":30}}`)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if tt.wantRefused {
				assert.Equal(t, http.StatusBadRequest, rec.Code, "body=%s", rec.Body.String())
				assert.Contains(t, rec.Body.String(), tt.keyAlgorithm)
				assert.Contains(t, rec.Body.String(), "cannot issue this key size or curve exactly")
				assert.False(t, asked, "the CA was asked to issue a refused key algorithm")
				assert.Zero(t, fakeKMS.generations, "the KMS generated a key for a refused key algorithm")
				return
			}

			require.Equal(t, http.StatusCreated, rec.Code, "body=%s", rec.Body.String())
			payload := decodeProtoBody(t, rec)
			certJSON, ok := payload["certificate"].(map[string]interface{})
			require.True(t, ok, "no certificate in the response")
			pemBytes, err := base64.StdEncoding.DecodeString(certJSON["pem"].(string))
			require.NoError(t, err)
			block, _ := pem.Decode(pemBytes)
			require.NotNil(t, block, "no certificate PEM in the response")
			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)

			switch {
			case tt.wantRSABits != 0:
				rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
				require.True(t, ok, "issued key is %T, want *rsa.PublicKey", cert.PublicKey)
				assert.Equal(t, tt.wantRSABits, rsaPub.N.BitLen())
			case tt.wantCurve != "":
				ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
				require.True(t, ok, "issued key is %T, want *ecdsa.PublicKey", cert.PublicKey)
				assert.Equal(t, tt.wantCurve, ecPub.Curve.Params().Name)
			case tt.wantEd25519:
				_, ok := cert.PublicKey.(ed25519.PublicKey)
				assert.True(t, ok, "issued key is %T, want ed25519.PublicKey", cert.PublicKey)
			}
		})
	}
}
