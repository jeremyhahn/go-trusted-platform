package measure

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

var signedAt = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

// testPKI is a root and a manifest-signing leaf under it, the leaf's key
// made by newKey.
type testPKI struct {
	roots *x509.CertPool
	chain []*x509.Certificate
	key   crypto.Signer
}

func newPKI(t *testing.T, newKey func() (crypto.Signer, error)) testPKI {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test platform CA"},
		NotBefore: signedAt.Add(-time.Hour), NotAfter: signedAt.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	key, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "manifest signer"},
		NotBefore: signedAt.Add(-time.Hour), NotAfter: signedAt.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return testPKI{roots: roots, chain: []*x509.Certificate{leaf, root}, key: key}
}

func p384() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) }

var testSigner = Signer{Name: "go-trusted-platform build", NotBefore: signedAt.Add(-time.Minute), NotAfter: signedAt.Add(time.Hour)}

func TestSignManifestRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		newKey func() (crypto.Signer, error)
		alg    int64
		sigLen int
	}{
		{"ES256", func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }, AlgES256, 64},
		{"ES384", p384, AlgES384, 96},
		{"ES512", func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P521(), rand.Reader) }, AlgES512, 132},
		{"PS256", func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 2048) }, AlgPS256, 256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pki := newPKI(t, tc.newKey)
			m := testManifest(t)
			data, err := SignManifest(m, pki.key, pki.chain, testSigner)
			if err != nil {
				t.Fatal(err)
			}
			msg, hdr := decodeSign1(t, data)
			if hdr.Alg != tc.alg || hdr.ContentType != ManifestContentType || len(hdr.X5Chain) != 2 || len(msg.Signature) != tc.sigLen {
				t.Fatalf("alg %d, content type %q, x5chain %d, signature %d bytes; want %d, %q, 2, %d",
					hdr.Alg, hdr.ContentType, len(hdr.X5Chain), len(msg.Signature), tc.alg, ManifestContentType, tc.sigLen)
			}
			payload, _ := EncodeManifest(m)
			if string(msg.Payload) != string(payload) {
				t.Fatal("the payload is not EncodeManifest's encoding")
			}
			got, err := VerifyManifest(data, pki.roots, signedAt)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Manifest, m) || got.Signer.Name != testSigner.Name ||
				!got.Signer.NotBefore.Equal(testSigner.NotBefore) || !got.Signer.NotAfter.Equal(testSigner.NotAfter) ||
				!got.Chain[0].Equal(pki.chain[0]) {
				t.Fatalf("verified %+v", got)
			}
		})
	}
}

// corim-meta's validity times are epoch-based, #6.1, as corim-11 types them.
func TestSignManifestCoRIMMeta(t *testing.T) {
	pki := newPKI(t, p384)
	data, err := SignManifest(testManifest(t), pki.key, pki.chain, testSigner)
	if err != nil {
		t.Fatal(err)
	}
	_, hdr := decodeSign1(t, data)
	diag, err := cbor.Diagnose(hdr.Meta)
	if err != nil {
		t.Fatal(err)
	}
	want := `{0: {0: "go-trusted-platform build"}, 1: {0: 1(1794657540), 1: 1(1794661200)}}`
	if diag != want {
		t.Fatalf("corim-meta %s, want %s", diag, want)
	}
}

func decodeSign1(t *testing.T, data []byte) (coseSign1, protectedHeader) {
	t.Helper()
	var outer cbor.RawTag
	var msg coseSign1
	var hdr protectedHeader
	if err := cbor.Unmarshal(data, &outer); err != nil || outer.Number != TagSignedCoRIM {
		t.Fatalf("outer tag %d (err %v)", outer.Number, err)
	}
	if err := cbor.Unmarshal(outer.Content, &msg); err != nil {
		t.Fatal(err)
	}
	if err := cbor.Unmarshal(msg.Protected, &hdr); err != nil {
		t.Fatal(err)
	}
	return msg, hdr
}

func encodeSign1(t *testing.T, msg coseSign1) []byte {
	t.Helper()
	out, err := encMode.Marshal(cbor.Tag{Number: TagSignedCoRIM, Content: msg})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSignManifestRefuses(t *testing.T) {
	pki := newPKI(t, p384)
	other := newPKI(t, p384)
	small := newPKI(t, func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 1024) })
	p224 := newPKI(t, func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P224(), rand.Reader) })
	for _, tc := range []struct {
		name   string
		key    crypto.Signer
		chain  []*x509.Certificate
		signer func(s *Signer)
		want   string
	}{
		{"no certificate", pki.key, nil, nil, "no signing certificate"},
		{"another key", other.key, pki.chain, nil, "the key is not the signing certificate's"},
		{"no signer name", pki.key, pki.chain, func(s *Signer) { s.Name = "" }, "no signer name"},
		{"no not-after", pki.key, pki.chain, func(s *Signer) { s.NotAfter = time.Time{} }, "no signature-validity not-after"},
		{"validity backwards", pki.key, pki.chain, func(s *Signer) { s.NotBefore = s.NotAfter.Add(time.Second) }, "ends before it starts"},
		{"a 1024-bit RSA key", small.key, small.chain, nil, "under 2048 bits"},
		{"a P-224 key", p224.key, p224.chain, nil, "not P-256, P-384 or P-521"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testSigner
			if tc.signer != nil {
				tc.signer(&s)
			}
			data, err := SignManifest(testManifest(t), tc.key, tc.chain, s)
			var se *SignatureError
			if !errors.As(err, &se) || !strings.Contains(err.Error(), tc.want) || data != nil {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
	m := testManifest(t)
	m.Model = ""
	var me *InvalidManifestError
	if _, err := SignManifest(m, pki.key, pki.chain, testSigner); !errors.As(err, &me) {
		t.Fatalf("an incomplete manifest: err %v", err)
	}
}

func TestVerifyManifestRefuses(t *testing.T) {
	pki := newPKI(t, p384)
	good, err := SignManifest(testManifest(t), pki.key, pki.chain, testSigner)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, _ := EncodeManifest(testManifest(t))
	// resign builds a COSE_Sign1 over a protected header edit made, signed
	// with pki's key, so only the edit is wrong.
	resign := func(t *testing.T, edit func(h *protectedHeader)) []byte {
		msg, hdr := decodeSign1(t, good)
		edit(&hdr)
		protected, err := encMode.Marshal(hdr)
		if err != nil {
			t.Fatal(err)
		}
		tbs, _ := toBeSigned(protected, msg.Payload)
		msg.Protected = protected
		if msg.Signature, err = sign(rand.Reader, pki.key, AlgES384, tbs); err != nil {
			t.Fatal(err)
		}
		return encodeSign1(t, msg)
	}
	for _, tc := range []struct {
		name  string
		data  func(t *testing.T) []byte
		roots *x509.CertPool
		at    time.Time
		want  string
	}{
		{"an unsigned CoRIM", func(*testing.T) []byte { return unsigned }, pki.roots, signedAt, "CBOR tag 501"},
		{"a changed payload", func(t *testing.T) []byte {
			msg, _ := decodeSign1(t, good)
			msg.Payload[len(msg.Payload)-1] ^= 1
			return encodeSign1(t, msg)
		}, pki.roots, signedAt, "the signature does not verify"},
		{"a changed signature", func(t *testing.T) []byte {
			msg, _ := decodeSign1(t, good)
			msg.Signature[0] ^= 1
			return encodeSign1(t, msg)
		}, pki.roots, signedAt, "the signature does not verify"},
		{"a detached payload", func(t *testing.T) []byte {
			msg, _ := decodeSign1(t, good)
			msg.Payload = nil
			return encodeSign1(t, msg)
		}, pki.roots, signedAt, "a detached payload"},
		{"another root", func(*testing.T) []byte { return good }, newPKI(t, p384).roots, signedAt, "the signing certificate does not verify"},
		{"before the signature-validity", func(*testing.T) []byte { return good }, pki.roots, testSigner.NotBefore.Add(-time.Second), "outside the signature-validity"},
		{"after the signature-validity", func(*testing.T) []byte { return good }, pki.roots, testSigner.NotAfter.Add(time.Second), "outside the signature-validity"},
		{"after the certificate", func(*testing.T) []byte { return good }, pki.roots, signedAt.Add(25 * time.Hour), "the signing certificate does not verify"},
		{"another algorithm", func(t *testing.T) []byte {
			return resign(t, func(h *protectedHeader) { h.Alg = AlgES256 })
		}, pki.roots, signedAt, "algorithm -7, but the signing key signs -35"},
		{"another content type", func(t *testing.T) []byte {
			return resign(t, func(h *protectedHeader) { h.ContentType = "application/cbor" })
		}, pki.roots, signedAt, `content type "application/cbor"`},
		{"another kid", func(t *testing.T) []byte {
			return resign(t, func(h *protectedHeader) { h.KID = make([]byte, 32) })
		}, pki.roots, signedAt, "the kid is not the signing certificate's"},
		{"no x5chain", func(t *testing.T) []byte {
			return resign(t, func(h *protectedHeader) { h.X5Chain = nil })
		}, pki.roots, signedAt, "no x5chain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := VerifyManifest(tc.data(t), tc.roots, tc.at)
			var se *SignatureError
			if !errors.As(err, &se) || !strings.Contains(err.Error(), tc.want) || got.Manifest.Banks != nil {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}
