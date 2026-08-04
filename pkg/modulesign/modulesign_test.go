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

package modulesign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- test fixtures -----------------------------------------------------------

func selfSigned(t *testing.T, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x0102030405),
		Subject:      pkix.Name{CommonName: "modulesign test signer"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31-1, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func rsaFixture(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key, selfSigned(t, key)
}

func ecdsaFixture(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key, selfSigned(t, key)
}

// --- parse helpers (mirror the package's own ASN.1 structs) ------------------

// splitEnvelope returns the CMS DER carved out of a BuildModuleSignature result.
func splitEnvelope(t *testing.T, out []byte) (cmsDER, trailer, marker []byte) {
	t.Helper()
	if len(out) < moduleSigTrailerLen+len(magic) {
		t.Fatalf("output too short: %d bytes", len(out))
	}
	marker = out[len(out)-len(magic):]
	trailer = out[len(out)-len(magic)-moduleSigTrailerLen : len(out)-len(magic)]
	cmsDER = out[:len(out)-len(magic)-moduleSigTrailerLen]
	return cmsDER, trailer, marker
}

func parseCMS(t *testing.T, cmsDER []byte) (signedData, signerInfo) {
	t.Helper()
	var ci contentInfo
	rest, err := asn1.Unmarshal(cmsDER, &ci)
	if err != nil {
		t.Fatalf("unmarshal ContentInfo: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes after ContentInfo: %d", len(rest))
	}
	if !ci.ContentType.Equal(oidSignedData) {
		t.Fatalf("ContentInfo type = %v, want id-signedData", ci.ContentType)
	}

	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("unmarshal SignedData: %v", err)
	}
	if len(sd.SignerInfos) != 1 {
		t.Fatalf("SignerInfos = %d, want 1", len(sd.SignerInfos))
	}
	return sd, sd.SignerInfos[0]
}

// signedAttrsSET reconstructs the universal SET OF (0x31) form that the kernel
// hashes when verifying the signature.
func signedAttrsSET(t *testing.T, si signerInfo) []byte {
	t.Helper()
	der, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      si.SignedAttrs.Bytes,
	})
	if err != nil {
		t.Fatalf("marshal signed attrs SET: %v", err)
	}
	return der
}

func messageDigestAttr(t *testing.T, si signerInfo) []byte {
	t.Helper()
	// Wrap the [0] IMPLICIT content in a SEQUENCE so it can be decoded as a slice
	// of attributes (SET OF and SEQUENCE OF share identical element encodings).
	seq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      si.SignedAttrs.Bytes,
	})
	if err != nil {
		t.Fatalf("marshal attrs SEQUENCE: %v", err)
	}
	var attrs []attribute
	if _, err := asn1.Unmarshal(seq, &attrs); err != nil {
		t.Fatalf("unmarshal attributes: %v", err)
	}
	for _, a := range attrs {
		if !a.Type.Equal(oidAttributeMessageDigest) {
			continue
		}
		var digest []byte
		if _, err := asn1.Unmarshal(a.Values.Bytes, &digest); err != nil {
			t.Fatalf("unmarshal messageDigest value: %v", err)
		}
		return digest
	}
	t.Fatal("messageDigest attribute not found")
	return nil
}

// --- tests -------------------------------------------------------------------

func TestModuleSignatureTrailer(t *testing.T) {
	key, cert := rsaFixture(t)
	content := []byte("golden trailer module contents")

	out, err := BuildModuleSignature(content, key, cert)
	if err != nil {
		t.Fatalf("BuildModuleSignature: %v", err)
	}

	cmsDER, trailer, marker := splitEnvelope(t, out)

	if len(magic) != 28 {
		t.Fatalf("magic length = %d, want 28", len(magic))
	}
	if string(marker) != "~Module signature appended~\n" {
		t.Fatalf("marker = %q, want the 28-byte magic", marker)
	}

	if len(trailer) != 12 {
		t.Fatalf("trailer length = %d, want 12", len(trailer))
	}
	for _, off := range []int{0, 1, 3, 4, 5, 6, 7} {
		if trailer[off] != 0 {
			t.Errorf("trailer byte %d = %d, want 0", off, trailer[off])
		}
	}
	if trailer[2] != 2 {
		t.Errorf("id_type = %d, want 2 (PKEY_ID_PKCS7)", trailer[2])
	}
	if got := binary.BigEndian.Uint32(trailer[8:12]); got != uint32(len(cmsDER)) {
		t.Errorf("sig_len = %d, want %d (big-endian len(cms_der))", got, len(cmsDER))
	}
}

func TestBuildModuleSignatureRoundTrip(t *testing.T) {
	key, cert := rsaFixture(t)
	content := []byte("the quick brown fox jumps over the lazy dog")

	out, err := BuildModuleSignature(content, key, cert)
	if err != nil {
		t.Fatalf("BuildModuleSignature: %v", err)
	}
	cmsDER, _, _ := splitEnvelope(t, out)

	sd, si := parseCMS(t, cmsDER)

	if sd.Version != 1 {
		t.Errorf("SignedData.Version = %d, want 1", sd.Version)
	}
	if si.Version != 1 {
		t.Errorf("SignerInfo.Version = %d, want 1", si.Version)
	}
	if !sd.EncapContentInfo.ContentType.Equal(oidData) {
		t.Errorf("eContentType = %v, want id-data", sd.EncapContentInfo.ContentType)
	}
	if len(sd.EncapContentInfo.Content.FullBytes) != 0 {
		t.Error("eContent present; detached CMS must omit it")
	}
	if len(sd.Certificates.FullBytes) != 0 {
		t.Error("certificates present; kernel format uses CMS_NOCERTS")
	}
	if !si.DigestAlgorithm.Algorithm.Equal(oidSHA256) {
		t.Errorf("digestAlgorithm = %v, want SHA-256", si.DigestAlgorithm.Algorithm)
	}
	if !si.SignatureAlgorithm.Algorithm.Equal(oidRSAEncryption) {
		t.Errorf("signatureAlgorithm = %v, want rsaEncryption", si.SignatureAlgorithm.Algorithm)
	}

	// Verify the RSA signature over the re-encoded signed attributes SET.
	setDER := signedAttrsSET(t, si)
	digest := sha256.Sum256(setDER)
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], si.Signature); err != nil {
		t.Fatalf("RSA signature over signed attributes failed to verify: %v", err)
	}

	// messageDigest attribute must equal SHA-256 of the module bytes.
	want := sha256.Sum256(content)
	if got := messageDigestAttr(t, si); !bytes.Equal(got, want[:]) {
		t.Errorf("messageDigest = %x, want %x", got, want)
	}
}

func TestBuildModuleSignatureDeterministic(t *testing.T) {
	key, cert := rsaFixture(t)
	content := []byte("deterministic across repeated invocations")

	out1, err := BuildModuleSignature(content, key, cert)
	if err != nil {
		t.Fatalf("BuildModuleSignature (1): %v", err)
	}
	out2, err := BuildModuleSignature(content, key, cert)
	if err != nil {
		t.Fatalf("BuildModuleSignature (2): %v", err)
	}
	if !bytes.Equal(out1, out2) {
		t.Fatal("output differs between identical key+content invocations")
	}
}

func TestBuildModuleSignatureECDSA(t *testing.T) {
	key, cert := ecdsaFixture(t)
	content := []byte("ecdsa-signed module contents")

	out, err := BuildModuleSignature(content, key, cert)
	if err != nil {
		t.Fatalf("BuildModuleSignature: %v", err)
	}
	cmsDER, _, _ := splitEnvelope(t, out)

	_, si := parseCMS(t, cmsDER)

	if !si.SignatureAlgorithm.Algorithm.Equal(oidECDSAWithSHA256) {
		t.Errorf("signatureAlgorithm = %v, want ecdsa-with-SHA256", si.SignatureAlgorithm.Algorithm)
	}
	if len(si.SignatureAlgorithm.Parameters.FullBytes) != 0 {
		t.Error("ecdsa-with-SHA256 must have absent parameters")
	}

	setDER := signedAttrsSET(t, si)
	digest := sha256.Sum256(setDER)
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], si.Signature) {
		t.Fatal("ECDSA signature over signed attributes failed to verify")
	}

	want := sha256.Sum256(content)
	if got := messageDigestAttr(t, si); !bytes.Equal(got, want[:]) {
		t.Errorf("messageDigest = %x, want %x", got, want)
	}
}

func TestBuildModuleSignatureNilInputs(t *testing.T) {
	_, cert := rsaFixture(t)
	key, _ := rsaFixture(t)

	if _, err := BuildModuleSignature([]byte("x"), nil, cert); !errors.As(err, &ErrNilSigner{}) {
		t.Errorf("nil signer error = %v, want ErrNilSigner", err)
	}
	if _, err := BuildModuleSignature([]byte("x"), key, nil); !errors.As(err, &ErrNilCertificate{}) {
		t.Errorf("nil certificate error = %v, want ErrNilCertificate", err)
	}
}

func TestSignatureAlgorithm(t *testing.T) {
	rsaKey, _ := rsaFixture(t)
	ecKey, _ := ecdsaFixture(t)

	if alg, err := signatureAlgorithm(rsaKey.Public()); err != nil || !alg.Algorithm.Equal(oidRSAEncryption) {
		t.Errorf("RSA: alg=%v err=%v, want rsaEncryption", alg.Algorithm, err)
	}
	if alg, err := signatureAlgorithm(ecKey.Public()); err != nil || !alg.Algorithm.Equal(oidECDSAWithSHA256) {
		t.Errorf("ECDSA: alg=%v err=%v, want ecdsa-with-SHA256", alg.Algorithm, err)
	}

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 GenerateKey: %v", err)
	}
	var ue ErrUnsupportedKeyType
	if _, err := signatureAlgorithm(edPub); !errors.As(err, &ue) {
		t.Errorf("ed25519 error = %v, want ErrUnsupportedKeyType", err)
	}
}

func TestSignModuleInPlace(t *testing.T) {
	key, cert := rsaFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "example.ko")
	content := []byte("\x7fELF fake module image bytes")
	const mode os.FileMode = 0o640
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := SignModule(path, key, cert); err != nil {
		t.Fatalf("SignModule: %v", err)
	}

	signed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.HasPrefix(signed, content) {
		t.Error("signed module does not start with original content")
	}
	if !bytes.HasSuffix(signed, []byte(magic)) {
		t.Error("signed module does not end with the magic marker")
	}
	if len(signed) <= len(content) {
		t.Error("signed module did not grow")
	}

	// The appended blob must match BuildModuleSignature exactly.
	want, err := BuildModuleSignature(content, key, cert)
	if err != nil {
		t.Fatalf("BuildModuleSignature: %v", err)
	}
	if !bytes.Equal(signed[len(content):], want) {
		t.Error("appended signature does not match BuildModuleSignature output")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != mode {
		t.Errorf("mode = %v, want %v", info.Mode().Perm(), mode)
	}
}

func TestSignModuleMissingFile(t *testing.T) {
	key, cert := rsaFixture(t)
	path := filepath.Join(t.TempDir(), "does-not-exist.ko")

	err := SignModule(path, key, cert)
	var re ErrModuleRead
	if !errors.As(err, &re) {
		t.Fatalf("error = %v, want ErrModuleRead", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error does not unwrap to os.ErrNotExist: %v", err)
	}
}

func TestEnumerateModules(t *testing.T) {
	key, cert := rsaFixture(t)
	root := t.TempDir()
	kver := "6.1.0-modulesign"
	base := filepath.Join(root, "lib", "modules", kver)
	drivers := filepath.Join(base, "kernel", "drivers")
	if err := os.MkdirAll(drivers, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	plainA := filepath.Join(base, "kernel", "a.ko")
	plainB := filepath.Join(drivers, "b.ko")
	compressed := filepath.Join(drivers, "c.ko.gz")
	for _, p := range []string{plainA, plainB} {
		if err := os.WriteFile(p, []byte("module"), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", p, err)
		}
	}
	gz, err := gzipCompress([]byte("compressed kernel module body"))
	if err != nil {
		t.Fatalf("gzipCompress: %v", err)
	}
	if err := os.WriteFile(compressed, gz, 0o644); err != nil {
		t.Fatalf("WriteFile %s: %v", compressed, err)
	}

	mods, err := EnumerateModules(root, kver)
	if err != nil {
		t.Fatalf("EnumerateModules: %v", err)
	}

	wantSet := map[string]bool{plainA: false, plainB: false, compressed: false}
	for _, m := range mods {
		if !filepath.IsAbs(m) {
			t.Errorf("module path is not absolute: %s", m)
		}
		if _, ok := wantSet[m]; !ok {
			t.Errorf("unexpected module path: %s", m)
			continue
		}
		wantSet[m] = true
	}
	for p, seen := range wantSet {
		if !seen {
			t.Errorf("module not enumerated: %s", p)
		}
	}

	// Compressed .ko.gz modules are enumerated AND signable in place: signing
	// rewrites the file with the signature appended to the decompressed image.
	if err := SignModule(compressed, key, cert); err != nil {
		t.Fatalf("SignModule(.ko.gz): %v", err)
	}
	signedRaw, err := os.ReadFile(compressed)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	decompressed, err := gzipDecompress(signedRaw)
	if err != nil {
		t.Fatalf("gzipDecompress signed module: %v", err)
	}
	if !bytes.HasSuffix(decompressed, []byte(magic)) {
		t.Error("signed .ko.gz does not carry the kernel magic on its decompressed payload")
	}
}

func TestEnumerateModulesMissingDir(t *testing.T) {
	_, err := EnumerateModules(t.TempDir(), "no-such-kver")
	var ee ErrEnumerate
	if !errors.As(err, &ee) {
		t.Fatalf("error = %v, want ErrEnumerate", err)
	}
}
