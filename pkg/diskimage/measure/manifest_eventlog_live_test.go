//go:build eventlog_live

package measure

import (
	"crypto/sha256"
	"crypto/x509"
	"io"
	"os"
	"testing"
	"time"
)

// TestBootEventLogMatchesTheSignedManifest checks a booted guest's event log
// against the signed measurement manifest of the image it booted:
//
//   - DISKIMAGE_IMAGE: the built image;
//   - DISKIMAGE_MANIFEST: its signed manifest, by default DISKIMAGE_IMAGE
//     with the ".corim" suffix the build writes;
//   - DISKIMAGE_MANIFEST_ROOTS: a PEM file of the CA roots the manifest's
//     signature verifies to;
//   - DISKIMAGE_EVENTLOG: the guest's binary_bios_measurements, copied out
//     after a boot.
//
// The CI job that boots the qemu-virt image under swtpm sets these (the next
// slice); nothing runs it yet.
func TestBootEventLogMatchesTheSignedManifest(t *testing.T) {
	imagePath := os.Getenv("DISKIMAGE_IMAGE")
	rootsPath := os.Getenv("DISKIMAGE_MANIFEST_ROOTS")
	logPath := os.Getenv("DISKIMAGE_EVENTLOG")
	switch {
	case imagePath == "":
		t.Skip("DISKIMAGE_IMAGE is not set")
	case rootsPath == "":
		t.Skip("DISKIMAGE_MANIFEST_ROOTS is not set")
	case logPath == "":
		t.Skip("DISKIMAGE_EVENTLOG is not set")
	}
	manifestPath := os.Getenv("DISKIMAGE_MANIFEST")
	if manifestPath == "" {
		manifestPath = imagePath + ".corim"
	}

	f, err := os.Open(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hashing %s: %v", imagePath, err)
	}

	signed, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(rootsPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatalf("%s holds no PEM certificate", rootsPath)
	}
	eventLog, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := CheckManifestEventLog(signed, h.Sum(nil), roots, time.Now(), eventLog); err != nil {
		t.Fatalf("%s against %s: %v", logPath, manifestPath, err)
	}
}
