package secureboot

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cov964Cause is a distinct cause so errors.Is proves the wrapped chain.
type cov964Cause struct{}

func (cov964Cause) Error() string { return "cov964 cause" }

func TestErrorMessagesAndUnwrap(t *testing.T) {
	cause := cov964Cause{}
	tests := []struct {
		name      string
		err       error
		wantMsg   string
		wantCause bool
	}{
		{
			name:      "WrappedError",
			err:       &WrappedError{Msg: "load", Err: cause},
			wantMsg:   "load: cov964 cause",
			wantCause: true,
		},
		{
			name:    "KMSKeyRefError",
			err:     &KMSKeyRefError{KeyURI: "file:///k"},
			wantMsg: `secureboot: key-uri "file:///k" is not a usable kms:// reference`,
		},
		{
			name:    "KMSPublicKeyError",
			err:     &KMSPublicKeyError{KeyID: "pk"},
			wantMsg: `secureboot: no public key for KMS key "pk"`,
		},
		{
			name:      "KMSCertificateError",
			err:       &KMSCertificateError{Ref: "kms://db", Err: cause},
			wantMsg:   `secureboot: certificate "kms://db": cov964 cause`,
			wantCause: true,
		},
		{
			name:      "KMSSignError",
			err:       &KMSSignError{KeyID: "db", Err: cause},
			wantMsg:   `secureboot: KMS sign with key "db": cov964 cause`,
			wantCause: true,
		},
		{
			name:    "UnsupportedHashError",
			err:     &UnsupportedHashError{Hash: "MD5"},
			wantMsg: `secureboot: unsupported hash "MD5" for KMS signing (want SHA-256/384/512)`,
		},
		{
			name:    "ErrModuleKeyExists",
			err:     ErrModuleKeyExists{Path: "/k.pem"},
			wantMsg: "secureboot: module-signing key already exists (use Force to overwrite): /k.pem",
		},
		{
			name:      "ErrModuleKeyNotFound",
			err:       ErrModuleKeyNotFound{Path: "/k.pem", Err: cause},
			wantMsg:   "secureboot: module-signing key not found: /k.pem: cov964 cause",
			wantCause: true,
		},
		{
			name:    "ErrModuleKeyMalformed",
			err:     ErrModuleKeyMalformed{Path: "/k.pem", Reason: "bad"},
			wantMsg: "secureboot: malformed module-signing key /k.pem: bad",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.wantMsg {
				t.Fatalf("Error() = %q, want %q", got, tc.wantMsg)
			}
			if got := errors.Is(tc.err, cause); got != tc.wantCause {
				t.Fatalf("errors.Is(cause) = %v, want %v", got, tc.wantCause)
			}
		})
	}
}

func TestLoadModuleSigningKey_MissingFileUnwrapsNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.pem")
	_, err := LoadModuleSigningKey(path)

	var notFound ErrModuleKeyNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("err = %v, want ErrModuleKeyNotFound", err)
	}
	if notFound.Path != path {
		t.Fatalf("Path = %q, want %q", notFound.Path, path)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want it to wrap fs.ErrNotExist", err)
	}
}

func TestLoadModuleSigningKey_MalformedBundles(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, MinModuleKeyBits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	junk := []byte{0x30, 0x03, 0x02, 0x01, 0x00}

	tests := []struct {
		name       string
		data       []byte
		wantReason string
	}{
		{
			name:       "invalid PKCS#8 key",
			data:       pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: junk}),
			wantReason: "invalid PKCS#8 private key",
		},
		{
			name:       "invalid PKCS#1 key",
			data:       pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: junk}),
			wantReason: "invalid PKCS#1 private key",
		},
		{
			name:       "invalid certificate",
			data:       append(append([]byte{}, pkcs1...), pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: junk})...),
			wantReason: "invalid certificate",
		},
		{
			name:       "PKCS#1 key without certificate",
			data:       pkcs1,
			wantReason: "no certificate PEM block found",
		},
		{
			name:       "no PEM at all",
			data:       []byte("not pem"),
			wantReason: "no private key PEM block found",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bundle.pem")
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			_, err := LoadModuleSigningKey(path)
			var malformed ErrModuleKeyMalformed
			if !errors.As(err, &malformed) {
				t.Fatalf("err = %v, want ErrModuleKeyMalformed", err)
			}
			if !strings.HasPrefix(malformed.Reason, tc.wantReason) {
				t.Fatalf("Reason = %q, want prefix %q", malformed.Reason, tc.wantReason)
			}
		})
	}
}

func TestWriteModuleSigningBundle_WriteFailures(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, MinModuleKeyBits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	cert, err := buildModuleSigningCert(key, "cov964", "", "", 1)
	if err != nil {
		t.Fatalf("buildModuleSigningCert: %v", err)
	}

	tests := []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{
			name: "parent is a regular file",
			setup: func(t *testing.T) string {
				parent := filepath.Join(t.TempDir(), "file")
				if err := os.WriteFile(parent, nil, 0600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				return filepath.Join(parent, "sub", "bundle.pem")
			},
		},
		{
			name: "path is a directory",
			setup: func(t *testing.T) string {
				return t.TempDir()
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := writeModuleSigningBundle(tc.setup(t), key, cert)
			if !errors.Is(err, ErrWriteFailed) {
				t.Fatalf("err = %v, want ErrWriteFailed", err)
			}
			var sc *SentinelCauseError
			if !errors.As(err, &sc) || sc.Cause == nil {
				t.Fatalf("err = %v, want a SentinelCauseError with a cause", err)
			}
		})
	}
}

func TestGenerateModuleSigningKey_UnwritablePath(t *testing.T) {
	_, err := GenerateModuleSigningKey(t.Context(), &ModuleSigningKeyConfig{
		Path:    t.TempDir(),
		KeyBits: MinModuleKeyBits,
		Force:   true,
	})
	if !errors.Is(err, ErrWriteFailed) {
		t.Fatalf("err = %v, want ErrWriteFailed", err)
	}
}
