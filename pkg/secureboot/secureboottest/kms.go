// Package secureboottest provides in-memory stand-ins for the platform KMS
// and CA a KMS-held Secure Boot key is reached through
// (secureboot.KMSSignClient, secureboot.CertificateGetter), and the key and
// certificate behind them, for the tests of the packages that sign with one.
package secureboottest

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// KeyPair returns a fresh RSA key and a self-signed certificate for it.
func KeyPair(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// PEM encodes cert.
func PEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// KMS signs pre-hashed SHA-256 digests with Key, as the platform KMS does
// with PreHashed set, recording the last request. Err and Empty fail it.
type KMS struct {
	Key     *rsa.PrivateKey
	LastReq *platformv1.SignRequest
	Err     error
	Empty   bool
}

// Sign implements secureboot.KMSSignClient.
func (k *KMS) Sign(_ context.Context, in *platformv1.SignRequest, _ ...grpc.CallOption) (*platformv1.SignResponse, error) {
	k.LastReq = in
	if k.Err != nil {
		return nil, k.Err
	}
	if k.Empty {
		return &platformv1.SignResponse{}, nil
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.Key, crypto.SHA256, in.GetMessage())
	if err != nil {
		return nil, err
	}
	return &platformv1.SignResponse{Signature: sig}, nil
}

// ErrNoCertificate is CA's answer for a reference it holds no certificate for.
var ErrNoCertificate = errors.New("secureboottest: no such certificate")

// CA serves certificates by reference, recording the last one asked for.
// Raw overrides the PEM returned for a reference (malformed-response tests).
type CA struct {
	Certs   map[string]*x509.Certificate
	Raw     map[string][]byte
	Err     error
	LastRef string
}

// GetCertificate implements secureboot.CertificateGetter.
func (c *CA) GetCertificate(_ context.Context, in *platformv1.GetCertificateRequest, _ ...grpc.CallOption) (*platformv1.GetCertificateResponse, error) {
	c.LastRef = in.GetSerial()
	if c.Err != nil {
		return nil, c.Err
	}
	if raw, ok := c.Raw[in.GetSerial()]; ok {
		if raw == nil {
			return &platformv1.GetCertificateResponse{}, nil
		}
		return &platformv1.GetCertificateResponse{Certificate: &platformv1.Certificate{Pem: raw}}, nil
	}
	cert, ok := c.Certs[in.GetSerial()]
	if !ok {
		return nil, ErrNoCertificate
	}
	return &platformv1.GetCertificateResponse{Certificate: &platformv1.Certificate{Pem: PEM(cert)}}, nil
}
