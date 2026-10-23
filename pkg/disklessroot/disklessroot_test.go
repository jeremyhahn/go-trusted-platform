package disklessroot

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testRootHash = "4f3c2a1b0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b"
	testSalt     = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
)

func testManifest() Manifest {
	return Manifest{
		Version:    ManifestVersion,
		RootHash:   testRootHash,
		Salt:       testSalt,
		RootFSSize: 64 * BlockSize,
		VeritySize: 2 * BlockSize,
	}
}

func selfSigned(t *testing.T, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "db"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(4102444800, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func testSigners(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	return map[string]crypto.Signer{"rsa": rsaKey, "ecdsa": ecKey, "ed25519": edKey}
}

func TestValidateRootHash(t *testing.T) {
	if err := ValidateRootHash(testRootHash); err != nil {
		t.Fatalf("valid root hash rejected: %v", err)
	}
	for name, value := range map[string]string{
		"empty":     "",
		"short":     testRootHash[:63],
		"long":      testRootHash + "0",
		"uppercase": strings.ToUpper(testRootHash),
		"not hex":   "z" + testRootHash[1:],
	} {
		t.Run(name, func(t *testing.T) {
			var fieldErr *FieldError
			if err := ValidateRootHash(value); !errors.As(err, &fieldErr) || fieldErr.Field != ParamRootHash {
				t.Fatalf("ValidateRootHash(%q) = %v, want a %s FieldError", value, err, ParamRootHash)
			}
		})
	}
}

func TestDeriveSaltIsDeterministicAndVersionBound(t *testing.T) {
	a := DeriveSalt(1700000000, "v1.2.3")
	if a != DeriveSalt(1700000000, "v1.2.3") {
		t.Fatal("the same epoch and version derived two salts")
	}
	if err := validateHex(ParamVeritySalt, a); err != nil {
		t.Fatalf("derived salt is not 64 hex characters: %v", err)
	}
	if a == DeriveSalt(1700000001, "v1.2.3") || a == DeriveSalt(1700000000, "v1.2.4") {
		t.Fatal("a different epoch or version derived the same salt")
	}
}

func TestManifestValidate(t *testing.T) {
	if err := testManifest().Validate(); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	cases := map[string]func(*Manifest){
		"version":          func(m *Manifest) { m.Version = 2 },
		"root hash":        func(m *Manifest) { m.RootHash = "abc" },
		"salt":             func(m *Manifest) { m.Salt = "" },
		"zero rootfs size": func(m *Manifest) { m.RootFSSize = 0 },
		"unaligned rootfs": func(m *Manifest) { m.RootFSSize = BlockSize + 1 },
		"zero verity size": func(m *Manifest) { m.VeritySize = 0 },
		"negative verity":  func(m *Manifest) { m.VeritySize = -1 },
		"negative rootfs":  func(m *Manifest) { m.RootFSSize = -BlockSize },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := testManifest()
			mutate(&m)
			var fieldErr *FieldError
			if err := m.Validate(); !errors.As(err, &fieldErr) {
				t.Fatalf("Validate() = %v, want a FieldError", err)
			}
		})
	}
}

func TestManifestDataBlocks(t *testing.T) {
	if got := testManifest().DataBlocks(); got != 64 {
		t.Fatalf("DataBlocks() = %d, want 64", got)
	}
}

func TestWriteAndReadSignedRoundTrip(t *testing.T) {
	for name, signer := range testSigners(t) {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := WriteSigned(dir, testManifest(), signer); err != nil {
				t.Fatalf("WriteSigned: %v", err)
			}
			got, err := ReadSigned(dir, selfSigned(t, signer))
			if err != nil {
				t.Fatalf("ReadSigned: %v", err)
			}
			if *got != testManifest() {
				t.Fatalf("ReadSigned = %+v, want %+v", *got, testManifest())
			}
		})
	}
}

func TestReadSignedRejectsATamperedManifest(t *testing.T) {
	signer := testSigners(t)["ecdsa"]
	dir := t.TempDir()
	if err := WriteSigned(dir, testManifest(), signer); err != nil {
		t.Fatalf("WriteSigned: %v", err)
	}
	path := filepath.Join(dir, ManifestFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	forged := strings.Replace(string(data), testRootHash, strings.Repeat("a", 64), 1)
	if err := os.WriteFile(path, []byte(forged), 0o644); err != nil {
		t.Fatalf("write forged manifest: %v", err)
	}
	var sigErr *SignatureError
	if _, err := ReadSigned(dir, selfSigned(t, signer)); !errors.As(err, &sigErr) {
		t.Fatalf("ReadSigned on a forged root hash = %v, want a SignatureError", err)
	}
}

func TestReadSignedRejectsAnotherSigner(t *testing.T) {
	signers := testSigners(t)
	dir := t.TempDir()
	if err := WriteSigned(dir, testManifest(), signers["rsa"]); err != nil {
		t.Fatalf("WriteSigned: %v", err)
	}
	var sigErr *SignatureError
	if _, err := ReadSigned(dir, selfSigned(t, signers["ecdsa"])); !errors.As(err, &sigErr) {
		t.Fatalf("ReadSigned with another key = %v, want a SignatureError", err)
	}
}

func TestReadSignedErrors(t *testing.T) {
	signer := testSigners(t)["ecdsa"]
	cert := selfSigned(t, signer)

	t.Run("missing manifest", func(t *testing.T) {
		var manifestErr *ManifestError
		if _, err := ReadSigned(t.TempDir(), cert); !errors.As(err, &manifestErr) {
			t.Fatalf("ReadSigned = %v, want a ManifestError", err)
		}
	})
	t.Run("missing signature", func(t *testing.T) {
		dir := t.TempDir()
		if err := WriteSigned(dir, testManifest(), signer); err != nil {
			t.Fatalf("WriteSigned: %v", err)
		}
		if err := os.Remove(filepath.Join(dir, SignatureFile)); err != nil {
			t.Fatalf("remove signature: %v", err)
		}
		var manifestErr *ManifestError
		if _, err := ReadSigned(dir, cert); !errors.As(err, &manifestErr) {
			t.Fatalf("ReadSigned = %v, want a ManifestError", err)
		}
	})
	t.Run("no anchor", func(t *testing.T) {
		dir := t.TempDir()
		if err := WriteSigned(dir, testManifest(), signer); err != nil {
			t.Fatalf("WriteSigned: %v", err)
		}
		var sigErr *SignatureError
		if _, err := ReadSigned(dir, nil); !errors.As(err, &sigErr) {
			t.Fatalf("ReadSigned without a certificate = %v, want a SignatureError", err)
		}
	})
	t.Run("signed but invalid", func(t *testing.T) {
		dir := t.TempDir()
		payload := []byte(`{"version":1,"root_hash":"` + testRootHash + `","salt":"nope","rootfs_size":4096,"verity_size":4096}`)
		writeSignedPayload(t, dir, payload, signer)
		var fieldErr *FieldError
		if _, err := ReadSigned(dir, cert); !errors.As(err, &fieldErr) {
			t.Fatalf("ReadSigned of a signed invalid manifest = %v, want a FieldError", err)
		}
	})
	t.Run("unknown field", func(t *testing.T) {
		dir := t.TempDir()
		payload := []byte(`{"version":1,"root_hash":"` + testRootHash + `","salt":"` + testSalt + `","rootfs_size":4096,"verity_size":4096,"url":"http://x"}`)
		writeSignedPayload(t, dir, payload, signer)
		var manifestErr *ManifestError
		if _, err := ReadSigned(dir, cert); !errors.As(err, &manifestErr) {
			t.Fatalf("ReadSigned with an unknown field = %v, want a ManifestError", err)
		}
	})
}

func TestWriteSignedErrors(t *testing.T) {
	signer := testSigners(t)["ecdsa"]
	t.Run("invalid manifest", func(t *testing.T) {
		bad := testManifest()
		bad.RootHash = ""
		var fieldErr *FieldError
		if err := WriteSigned(t.TempDir(), bad, signer); !errors.As(err, &fieldErr) {
			t.Fatalf("WriteSigned = %v, want a FieldError", err)
		}
	})
	t.Run("no signer", func(t *testing.T) {
		var sigErr *SignatureError
		if err := WriteSigned(t.TempDir(), testManifest(), nil); !errors.As(err, &sigErr) {
			t.Fatalf("WriteSigned = %v, want a SignatureError", err)
		}
	})
	t.Run("unwritable directory", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(missing, nil, 0o644); err != nil {
			t.Fatalf("create file: %v", err)
		}
		var manifestErr *ManifestError
		if err := WriteSigned(missing, testManifest(), signer); !errors.As(err, &manifestErr) {
			t.Fatalf("WriteSigned into a file = %v, want a ManifestError", err)
		}
	})
}

func writeSignedPayload(t *testing.T, dir string, payload []byte, signer crypto.Signer) {
	t.Helper()
	sig, err := sign(payload, signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), payload, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, SignatureFile), sig, 0o644); err != nil {
		t.Fatalf("write signature: %v", err)
	}
}
