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

package quic

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	tpmgo "github.com/google/go-tpm/tpm2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// credMockTPM records the arguments passed to the credential primitives and
// returns canned values, so the handlers can be asserted to pass through to
// the backing TPM module.
type credMockTPM struct {
	xkmssdk.TrustedPlatformModule

	gotAKName    []byte
	gotSecret    []byte
	gotEKCert    *x509.Certificate
	gotIAKPub    []byte
	usedExtEK    bool
	makeErr      error
	makeBlob     []byte
	makeEnc      []byte
	makeSecret   []byte
	gotCredBlob  []byte
	gotEncSecret []byte
	activateErr  error
	activateOut  []byte
}

func (m *credMockTPM) MakeCredential(akName tpmgo.TPM2BName, secret []byte) ([]byte, []byte, []byte, error) {
	m.gotAKName = akName.Buffer
	m.gotSecret = secret
	return m.makeBlob, m.makeEnc, m.makeSecret, m.makeErr
}

func (m *credMockTPM) MakeCredentialWithExternalEK(ekCert *x509.Certificate, iakPubBytes, secret []byte) ([]byte, []byte, []byte, error) {
	m.usedExtEK = true
	m.gotEKCert = ekCert
	m.gotIAKPub = iakPubBytes
	m.gotSecret = secret
	return m.makeBlob, m.makeEnc, m.makeSecret, m.makeErr
}

func (m *credMockTPM) ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error) {
	m.gotCredBlob = credentialBlob
	m.gotEncSecret = encryptedSecret
	return m.activateOut, m.activateErr
}

func newCredHandler(tpm xkmssdk.TrustedPlatformModule) *TPM2Handler {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(tpm)
	return h
}

func mustEncode(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := EncodePayload(v)
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	return b
}

func TestTPM2Handler_MakeCredential_LocalEK(t *testing.T) {
	mock := &credMockTPM{
		makeBlob:   []byte("blob"),
		makeEnc:    []byte("enc"),
		makeSecret: []byte("secret"),
	}
	h := newCredHandler(mock)

	reqBody := mustEncode(t, &TPM2MakeCredentialRequest{
		AKName: []byte("ak-name"),
		Secret: []byte("seed"),
	})
	payload := append([]byte{SubOpTPM2MakeCred}, reqBody...)

	resp := h.HandleMessage(context.Background(), &Request{Payload: payload})
	if resp.Status != StatusOK {
		t.Fatalf("status = %d, body=%s", resp.Status, resp.Payload)
	}
	if mock.usedExtEK {
		t.Fatal("expected local-EK path, got external-EK path")
	}
	if !bytes.Equal(mock.gotAKName, []byte("ak-name")) {
		t.Fatalf("ak name not passed through: %q", mock.gotAKName)
	}
	if !bytes.Equal(mock.gotSecret, []byte("seed")) {
		t.Fatalf("secret not passed through: %q", mock.gotSecret)
	}

	var out TPM2MakeCredentialResponse
	if err := DecodePayload(resp.Payload, &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !bytes.Equal(out.CredentialBlob, mock.makeBlob) ||
		!bytes.Equal(out.EncryptedSecret, mock.makeEnc) ||
		!bytes.Equal(out.Secret, mock.makeSecret) {
		t.Fatalf("response did not carry backing values: %+v", out)
	}
}

func TestTPM2Handler_MakeCredential_ExternalEK(t *testing.T) {
	// Build a throwaway self-signed cert so x509.ParseCertificate succeeds.
	der := selfSignedDER(t)
	mock := &credMockTPM{
		makeBlob:   []byte("xblob"),
		makeEnc:    []byte("xenc"),
		makeSecret: []byte("xsecret"),
	}
	h := newCredHandler(mock)

	reqBody := mustEncode(t, &TPM2MakeCredentialRequest{
		EKCert: der,
		IAKPub: []byte("iak-pub"),
		Secret: []byte("seed"),
	})
	payload := append([]byte{SubOpTPM2MakeCred}, reqBody...)

	resp := h.HandleMessage(context.Background(), &Request{Payload: payload})
	if resp.Status != StatusOK {
		t.Fatalf("status = %d, body=%s", resp.Status, resp.Payload)
	}
	if !mock.usedExtEK {
		t.Fatal("expected external-EK path")
	}
	if mock.gotEKCert == nil {
		t.Fatal("ek cert not parsed/passed through")
	}
	if !bytes.Equal(mock.gotIAKPub, []byte("iak-pub")) {
		t.Fatalf("iak pub not passed through: %q", mock.gotIAKPub)
	}
}

func TestTPM2Handler_MakeCredential_Error(t *testing.T) {
	mock := &credMockTPM{makeErr: errors.New("tpm failure")}
	h := newCredHandler(mock)
	reqBody := mustEncode(t, &TPM2MakeCredentialRequest{AKName: []byte("ak")})
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2MakeCred}, reqBody...)})
	if resp.Status == StatusOK {
		t.Fatal("expected error status for failing MakeCredential")
	}
}

func TestTPM2Handler_ActivateCredential(t *testing.T) {
	mock := &credMockTPM{activateOut: []byte("recovered")}
	h := newCredHandler(mock)

	reqBody := mustEncode(t, &TPM2ActivateCredentialRequest{
		CredentialBlob:  []byte("cred"),
		EncryptedSecret: []byte("enc"),
	})
	payload := append([]byte{SubOpTPM2ActivateCred}, reqBody...)

	resp := h.HandleMessage(context.Background(), &Request{Payload: payload})
	if resp.Status != StatusOK {
		t.Fatalf("status = %d, body=%s", resp.Status, resp.Payload)
	}
	if !bytes.Equal(mock.gotCredBlob, []byte("cred")) || !bytes.Equal(mock.gotEncSecret, []byte("enc")) {
		t.Fatal("activate args not passed through to backing tpm")
	}

	var out TPM2ActivateCredentialResponse
	if err := DecodePayload(resp.Payload, &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !bytes.Equal(out.Secret, []byte("recovered")) {
		t.Fatalf("secret not returned: %q", out.Secret)
	}
}

func TestTPM2Handler_ActivateCredential_MissingFields(t *testing.T) {
	h := newCredHandler(&credMockTPM{})
	reqBody := mustEncode(t, &TPM2ActivateCredentialRequest{EncryptedSecret: []byte("enc")})
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2ActivateCred}, reqBody...)})
	if resp.Status == StatusOK {
		t.Fatal("expected error for missing credential_blob")
	}
}

// selfSignedDER returns a DER-encoded throwaway self-signed certificate for
// exercising the external-EK MakeCredential path (only x509 parsing is hit).
func selfSignedDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}
