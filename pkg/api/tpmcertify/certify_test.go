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

package tpmcertify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	tpmgo "github.com/google/go-tpm/tpm2"
	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ssrkHandle is the Shared SRK the SDK provisions under the default config.
const ssrkHandle uint32 = 0x81000001

// signedCertifyResult builds what the SDK returns for a TPM2_Certify: a
// TPMS_ATTEST over the nonce, signed by a stand-in IAK.
func signedCertifyResult(t *testing.T, nonce []byte) *quicbaassdk.CertifyResult {
	t.Helper()
	iak, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate IAK: %v", err)
	}
	certified, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate certified key: %v", err)
	}
	info := tpmgo.Marshal(tpmgo.TPMSAttest{
		Magic:     tpmgo.TPMGeneratedValue,
		Type:      tpmgo.TPMSTAttestCertify,
		ExtraData: tpmgo.TPM2BData{Buffer: nonce},
		Attested: tpmgo.NewTPMUAttest(tpmgo.TPMSTAttestCertify, &tpmgo.TPMSCertifyInfo{
			Name: tpmgo.TPM2BName{Buffer: []byte{0x00, 0x0b, 0x01}},
		}),
	})
	digest := sha256.Sum256(info)
	signature, err := ecdsa.SignASN1(rand.Reader, iak, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return &quicbaassdk.CertifyResult{
		CertifyInfo:            info,
		Signature:              signature,
		SignatureAlgorithm:     x509.ECDSAWithSHA256,
		AttestingKeyPublic:     &iak.PublicKey,
		AttestedKeyPublic:      &certified.PublicKey,
		Nonce:                  nonce,
		CertifyInfoSignature:   []byte("TPMT_SIGNATURE"),
		AttestingKeyPublicArea: []byte("IAK TPMT_PUBLIC"),
		AttestedKeyPublicArea:  []byte("key TPMT_PUBLIC"),
	}
}

func TestCertifyReturnsAVerifiableAttestation(t *testing.T) {
	nonce := []byte("certify-freshness-nonce")
	sdkResult := signedCertifyResult(t, nonce)
	tpm := &fakeCertifier{result: sdkResult}

	res, err := Certify(tpm, ssrkHandle, "", nonce)
	if err != nil {
		t.Fatalf("Certify: %v", err)
	}

	attest, err := tpmgo.Unmarshal[tpmgo.TPMSAttest](res.CertifyInfo)
	if err != nil {
		t.Fatalf("certify_info is not a TPMS_ATTEST: %v", err)
	}
	if !bytes.Equal(attest.ExtraData.Buffer, nonce) || !bytes.Equal(res.Nonce, nonce) {
		t.Fatalf("the nonce must be echoed: extraData %q, Nonce %q", attest.ExtraData.Buffer, res.Nonce)
	}
	if res.SignatureAlgorithm != x509.ECDSAWithSHA256.String() {
		t.Fatalf("SignatureAlgorithm = %q, want %q", res.SignatureAlgorithm, x509.ECDSAWithSHA256.String())
	}
	attestingKey, err := x509.ParsePKIXPublicKey(res.AttestingKeyPublic)
	if err != nil {
		t.Fatalf("attesting key is not PKIX DER: %v", err)
	}
	ecKey, ok := attestingKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("attesting key is %T, want *ecdsa.PublicKey", attestingKey)
	}
	digest := sha256.Sum256(res.CertifyInfo)
	if !ecdsa.VerifyASN1(ecKey, digest[:], res.Signature) {
		t.Fatal("signature does not verify under the attesting key")
	}
	attestedKey, err := x509.ParsePKIXPublicKey(res.AttestedKeyPublic)
	if err != nil {
		t.Fatalf("attested key is not PKIX DER: %v", err)
	}
	if !attestedKey.(*ecdsa.PublicKey).Equal(sdkResult.AttestedKeyPublic) {
		t.Fatal("attested key must be the certified key")
	}
	if string(res.CertifyInfoSignature) != "TPMT_SIGNATURE" ||
		string(res.AttestingKeyPublicArea) != "IAK TPMT_PUBLIC" ||
		string(res.AttestedKeyPublicArea) != "key TPMT_PUBLIC" {
		t.Fatal("marshalled TPMT_SIGNATURE and TPMT_PUBLIC areas must pass through")
	}
}

func TestCertifyMissingKeyIsNotFound(t *testing.T) {
	tpm := &fakeCertifier{err: fmt.Errorf("failed to read persistent key public: %w", tpmgo.TPMRCHandle)}

	_, err := Certify(tpm, 0x81FFFFF0, "", nil)

	var notFound ErrKeyNotFound
	if !errors.As(err, &notFound) || notFound.Handle != 0x81FFFFF0 {
		t.Fatalf("err = %v, want ErrKeyNotFound for 0x81FFFFF0", err)
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}

// fakeCertifier returns a canned SDK result or error and records the key
// attributes it was asked to certify.
type fakeCertifier struct {
	cfg    *quicbaassdk.TPMConfig
	result *quicbaassdk.CertifyResult
	err    error
	got    *quicbaassdk.KeyAttributes
}

func (f *fakeCertifier) CertifyKey(keyAttrs *quicbaassdk.KeyAttributes, _ []byte, _ quicbaassdk.TPMKeyBackend) (*quicbaassdk.CertifyResult, error) {
	f.got = keyAttrs
	return f.result, f.err
}

func (f *fakeCertifier) Config() *quicbaassdk.TPMConfig { return f.cfg }

func TestCertifyRejectsBadRequests(t *testing.T) {
	tests := []struct {
		name   string
		tpm    Certifier
		handle uint32
		nonce  []byte
		want   error
		code   codes.Code
	}{
		{"no TPM", nil, ssrkHandle, nil, ErrTPMUnavailable{}, codes.Unavailable},
		{"handle zero", &fakeCertifier{}, 0, nil, ErrHandleRequired{}, codes.InvalidArgument},
		{"transient handle", &fakeCertifier{}, 0x80000001, nil, ErrHandleNotPersistent{Handle: 0x80000001}, codes.InvalidArgument},
		{"NV index", &fakeCertifier{}, 0x01C00002, nil, ErrHandleNotPersistent{Handle: 0x01C00002}, codes.InvalidArgument},
		{"nonce too large", &fakeCertifier{}, ssrkHandle, make([]byte, MaxNonceSize+1), ErrNonceTooLarge{Size: MaxNonceSize + 1}, codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Certify(tt.tpm, tt.handle, "", tt.nonce)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if status.Code(err) != tt.code {
				t.Fatalf("code = %v, want %v", status.Code(err), tt.code)
			}
		})
	}
}

func TestCertifyWrapsSDKError(t *testing.T) {
	sdkErr := errors.New("IAK not provisioned")
	tpm := &fakeCertifier{err: sdkErr}

	_, err := Certify(tpm, ssrkHandle, "", nil)

	var failed ErrCertifyFailed
	if !errors.As(err, &failed) || !errors.Is(err, sdkErr) {
		t.Fatalf("err = %v, want ErrCertifyFailed wrapping the SDK error", err)
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
}

func TestCertifyNamesTheKeyForTheSDK(t *testing.T) {
	idevid := uint32(0x81020000)
	tpm := &fakeCertifier{
		cfg: &quicbaassdk.TPMConfig{IDevID: &quicbaassdk.IDevIDConfig{Handle: idevid}},
		err: errors.New("stop after recording"),
	}

	if _, err := Certify(tpm, idevid, "key-secret", nil); err == nil {
		t.Fatal("want the canned SDK error")
	}
	if tpm.got.TPMAttributes.Handle != tpmgo.TPMHandle(idevid) {
		t.Fatalf("handle = 0x%08X, want 0x%08X", tpm.got.TPMAttributes.Handle, idevid)
	}
	if tpm.got.KeyType != quicbaassdk.KeyTypeIDevID {
		t.Fatalf("KeyType = %v, want IDevID for the configured IDevID handle", tpm.got.KeyType)
	}
	if tpm.got.Password == nil || string(tpm.got.Password.Bytes()) != "key-secret" {
		t.Fatal("the key password must reach the SDK")
	}

	if _, err := Certify(tpm, ssrkHandle, "", nil); err == nil {
		t.Fatal("want the canned SDK error")
	}
	if tpm.got.KeyType == quicbaassdk.KeyTypeIDevID || tpm.got.Password != nil {
		t.Fatal("an ordinary key without a password must carry neither the IDevID type nor a password")
	}
}

func TestCertifyRejectsUnmarshallablePublicKey(t *testing.T) {
	tpm := &fakeCertifier{result: &quicbaassdk.CertifyResult{AttestingKeyPublic: "not a key"}}

	_, err := Certify(tpm, ssrkHandle, "", nil)

	var failed ErrCertifyFailed
	if !errors.As(err, &failed) {
		t.Fatalf("err = %v, want ErrCertifyFailed", err)
	}
}
