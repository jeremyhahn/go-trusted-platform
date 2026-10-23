package diskimage

import (
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxDERKeyBytes bounds the files tried as a bare DER private key. The
// largest key the platform handles, RSA-8192 in PKCS#8, is under 5 KiB.
const maxDERKeyBytes = 16 << 10

// DisklessRootPrivateKeyError reports private key material in a diskless
// root. The root is served to every node that boots the media set, so a key
// in it is a key every node — and anyone who can fetch the image — holds.
type DisklessRootPrivateKeyError struct {
	// Path is relative to the root.
	Path string
	// Kind says what gave the key away.
	Kind string
}

func (e DisklessRootPrivateKeyError) Error() string {
	return "diskless root: /" + e.Path + " holds private key material (" + e.Kind + "); the root is public"
}

// refuseRootPrivateKeys walks the tree about to be packed and refuses the first
// file that is, or carries, a private key: a *.key file whatever it holds, a
// PEM block of any PRIVATE KEY type anywhere in a file, or a whole file that
// parses as a DER PKCS#8, PKCS#1 or SEC 1 private key. Symlinks are not
// followed: their targets are either in the tree, and walked, or outside it,
// and not in the image.
func refuseRootPrivateKeys(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if strings.EqualFold(filepath.Ext(path), ".key") {
			return DisklessRootPrivateKeyError{Path: rel, Kind: "a *.key file"}
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if kind := privateKeyKind(data); kind != "" {
			return DisklessRootPrivateKeyError{Path: rel, Kind: kind}
		}
		return nil
	})
}

// privateKeyKind names the private key data carries, or is empty.
func privateKeyKind(data []byte) string {
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			return "a PEM " + block.Type + " block"
		}
	}
	if len(data) > maxDERKeyBytes {
		return ""
	}
	if _, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		return "a DER PKCS#8 private key"
	}
	if _, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return "a DER PKCS#1 private key"
	}
	if _, err := x509.ParseECPrivateKey(data); err == nil {
		return "a DER SEC 1 private key"
	}
	return ""
}
