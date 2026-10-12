package diskimage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// keyMaterial is one encoding of a freshly generated private key.
type keyMaterial struct {
	ecPKCS8, ecSEC1, rsaPKCS1 []byte
}

func newKeyMaterial(t *testing.T) keyMaterial {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	return keyMaterial{ecPKCS8: pkcs8, ecSEC1: sec1, rsaPKCS1: x509.MarshalPKCS1PrivateKey(rsaKey)}
}

func pemBlock(kind string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}))
}

// writeTree lays files, relative path to content, under a new directory.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestRefusePrivateKeysPassesAPublicTree(t *testing.T) {
	_, cert := testDBKey(t)
	root := writeTree(t, map[string]string{
		"etc/trusted-platform/ca-bundle.pem":  pemBlock("CERTIFICATE", cert.Raw),
		"etc/trusted-platform/secure-boot/db": string(cert.Raw),
		"etc/apk/keys/alpine.rsa.pub":         pemBlock("PUBLIC KEY", cert.RawSubjectPublicKeyInfo),
		// A binary names the PEM type it parses; it carries no key.
		"usr/bin/platformd": "\x7fELF\x00-----BEGIN RSA PRIVATE KEY-----\x00ParsePKCS1PrivateKey\x00",
		"etc/keymap":        "us",
	})
	if err := os.Symlink("/var/lib/trusted-platform/node.key", filepath.Join(root, "etc", "node.key")); err != nil {
		t.Fatal(err)
	}
	if err := refuseRootPrivateKeys(root); err != nil {
		t.Fatalf("refuseRootPrivateKeys: %v", err)
	}
}

func TestRefusePrivateKeysRefusesKeyMaterial(t *testing.T) {
	keys := newKeyMaterial(t)
	_, cert := testDBKey(t)
	cases := map[string]struct {
		path, content string
	}{
		"PEM PKCS#8":                   {"etc/ssl/private/node.pem", pemBlock("PRIVATE KEY", keys.ecPKCS8)},
		"PEM EC":                       {"root/ec.pem", pemBlock("EC PRIVATE KEY", keys.ecSEC1)},
		"PEM RSA":                      {"root/rsa.pem", pemBlock("RSA PRIVATE KEY", keys.rsaPKCS1)},
		"PEM encrypted":                {"root/enc.pem", pemBlock("ENCRYPTED PRIVATE KEY", []byte("ciphertext"))},
		"PEM OpenSSH":                  {"etc/ssh/ssh_host_ed25519_key", pemBlock("OPENSSH PRIVATE KEY", []byte("openssh-key-v1"))},
		"PEM after a certificate":      {"etc/bundle.pem", pemBlock("CERTIFICATE", cert.Raw) + "junk\n" + pemBlock("PRIVATE KEY", keys.ecPKCS8)},
		"DER PKCS#8":                   {"etc/trusted-platform/db.der", string(keys.ecPKCS8)},
		"DER EC":                       {"etc/trusted-platform/ec.der", string(keys.ecSEC1)},
		"DER RSA":                      {"etc/trusted-platform/rsa.der", string(keys.rsaPKCS1)},
		"generated Secure Boot DB.key": {"etc/trusted-platform/secure-boot/DB.key", "anything"},
		"an empty upper-case .KEY":     {"opt/x/SIGNING.KEY", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := writeTree(t, map[string]string{"etc/hostname": "node", tc.path: tc.content})
			err := refuseRootPrivateKeys(root)
			var found DisklessRootPrivateKeyError
			if !errors.As(err, &found) {
				t.Fatalf("err = %v, want a DisklessRootPrivateKeyError", err)
			}
			if found.Path != tc.path {
				t.Errorf("Path = %q, want %q", found.Path, tc.path)
			}
		})
	}
}

func TestRefusePrivateKeysReportsAnUnreadableTree(t *testing.T) {
	err := refuseRootPrivateKeys(filepath.Join(t.TempDir(), "missing"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want fs.ErrNotExist", err)
	}
	var found DisklessRootPrivateKeyError
	if errors.As(err, &found) {
		t.Errorf("an unreadable tree was reported as key material: %v", err)
	}
}

func TestDisklessRootPrivateKeyErrorNamesThePath(t *testing.T) {
	err := DisklessRootPrivateKeyError{Path: "etc/secure-boot/DB.key", Kind: "a *.key file"}
	want := "diskless root: /etc/secure-boot/DB.key holds private key material (a *.key file); the root is public"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestGenerateDisklessRootRefusesAPrivateKey(t *testing.T) {
	rec := newDisklessRunner()
	rec.tree["etc/trusted-platform/secure-boot/DB.key"] = "generated"
	_, err := GenerateDisklessRoot(context.Background(), disklessOptions(t, rec, &fakeAssemble{parts: 2}))
	var stage *StageError
	var found DisklessRootPrivateKeyError
	if !errors.As(err, &stage) || stage.Step != "checking the installed root for private keys" || !errors.As(err, &found) {
		t.Fatalf("err = %v, want the private-key check to refuse the root", err)
	}
	if slices.ContainsFunc(rec.calls, func(c string) bool { return strings.HasPrefix(c, "mksquashfs") }) {
		t.Error("a root holding a private key was packed")
	}
	if !slices.Contains(rec.calls, "losetup --detach "+testLoop) {
		t.Error("the root partition was left attached")
	}
}

func TestDisklessInstallNeverGeneratesSecureBootKeys(t *testing.T) {
	// The in-container install signs nothing: with Secure Boot on it would
	// generate a DB key onto the root it is about to publish.
	rec, asm := newDisklessRunner(), &fakeAssemble{parts: 2}
	opts := disklessOptions(t, rec, asm)
	opts.Config.SecureBoot = &installer.SecureBootConfig{Enabled: true, Enforce: true}
	if _, err := GenerateDisklessRoot(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if asm.cfg.SecureBoot == nil || asm.cfg.SecureBoot.Enabled || asm.cfg.SecureBoot.Enforce {
		t.Errorf("installed with Secure Boot %+v, want it off", asm.cfg.SecureBoot)
	}
	if !opts.Config.SecureBoot.Enabled || !opts.Config.SecureBoot.Enforce {
		t.Errorf("the caller's Secure Boot configuration was modified: %+v", opts.Config.SecureBoot)
	}

	// No Secure Boot section stays none.
	asm = &fakeAssemble{parts: 2}
	if _, err := GenerateDisklessRoot(context.Background(), disklessOptions(t, newDisklessRunner(), asm)); err != nil {
		t.Fatal(err)
	}
	if asm.cfg.SecureBoot != nil {
		t.Errorf("Secure Boot = %+v, want none", asm.cfg.SecureBoot)
	}
}
