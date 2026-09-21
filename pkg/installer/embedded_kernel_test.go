package installer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

// writeSecureBootKeyPair writes a self-signed RSA DB key pair as PEM files
// and returns their file:// URIs, the way a platform config names them.
func writeSecureBootKeyPair(t *testing.T) (keyURI, certURI string, cert *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "Trusted Platform - Database Key (test)"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err = x509.ParseCertificate(der)
	require.NoError(t, err)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "DB.key")
	certPath := filepath.Join(dir, "DB.crt")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600))
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	return "file://" + keyPath, "file://" + certPath, cert
}

// closeRecorder is a kernel reader that records whether it was closed.
type closeRecorder struct {
	io.Reader
	closed bool
}

func (c *closeRecorder) Close() error { c.closed = true; return nil }

func newSigningInstaller(t *testing.T, firmware BootFirmwareType, secureBoot bool) (*installer, *x509.Certificate) {
	t.Helper()
	keyURI, certURI, cert := writeSecureBootKeyPair(t)
	sb := &SecureBootConfig{Enabled: secureBoot}
	sb.DB.KeyURI = keyURI
	sb.DB.CertURI = certURI
	return &installer{
		logger: logging.DefaultLogger(),
		config: &Config{
			Boot:       &BootConfig{Firmware: firmware},
			SecureBoot: sb,
		},
	}, cert
}

func TestVerifiesEmbeddedKernel(t *testing.T) {
	assert.False(t, uefiFirmware{}.VerifiesEmbeddedKernel(), "EDK2 honours the stub's security override")
	assert.True(t, ubootFirmware{}.VerifiesEmbeddedKernel(), "U-Boot authenticates the inner kernel")
}

func TestSignEmbeddedKernel_SignsForUBoot(t *testing.T) {
	inst, cert := newSigningInstaller(t, BootFirmwareUBoot, true)
	kernel := &closeRecorder{Reader: bytes.NewReader(authenticodetest.MinimalPE(authenticodetest.MachineARM64))}
	u := &uki.UKI{Kernel: kernel, Cmdline: "root=/dev/mapper/vg0-root"}

	require.NoError(t, inst.signEmbeddedKernel(context.Background(), ubootFirmware{}, u))

	assert.True(t, kernel.closed, "the original kernel file is closed once read")
	signed, err := io.ReadAll(u.Kernel)
	require.NoError(t, err)
	assert.Greater(t, len(signed), 4096, "the kernel grew by its certificate table")

	// What was embedded verifies against the DB certificate.
	key, err := parsePEMPrivateKey(fileURIPath(inst.config.SecureBoot.DB.KeyURI))
	require.NoError(t, err)
	verifier, err := inst.newAuthenticodeSigner(context.Background(), key, cert)
	require.NoError(t, err)
	assert.NoError(t, verifier.Verify(bytes.NewReader(signed)))
}

func TestSignEmbeddedKernel_LeavesTheKernelAlone(t *testing.T) {
	original := authenticodetest.MinimalPE(authenticodetest.MachineARM64)
	cases := []struct {
		name     string
		firmware BootFirmwareType
		fw       bootFirmware
		sb       bool
	}{
		{"UEFI firmware", BootFirmwareUEFI, uefiFirmware{}, true},
		{"U-Boot with Secure Boot disabled", BootFirmwareUBoot, ubootFirmware{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst, _ := newSigningInstaller(t, tc.firmware, tc.sb)
			kernel := &closeRecorder{Reader: bytes.NewReader(original)}
			u := &uki.UKI{Kernel: kernel}

			require.NoError(t, inst.signEmbeddedKernel(context.Background(), tc.fw, u))

			assert.Same(t, kernel, u.Kernel, "the kernel reader is untouched")
			assert.False(t, kernel.closed)
		})
	}
}

func TestSignEmbeddedKernel_UnreadableKernelFails(t *testing.T) {
	inst, _ := newSigningInstaller(t, BootFirmwareUBoot, true)
	u := &uki.UKI{Kernel: bytes.NewReader([]byte("not a PE image"))}

	err := inst.signEmbeddedKernel(context.Background(), ubootFirmware{}, u)

	require.Error(t, err)
	var installerErr *InstallerError
	require.ErrorAs(t, err, &installerErr)
	assert.Equal(t, ErrorTypeUKIBuild, installerErr.Type)
}
