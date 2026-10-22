package installer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func loadTPMSealConfig(t *testing.T, body string) *TPMSealConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
	cfg, err := LoadConfig(path)
	require.NoError(t, err)
	require.NotNil(t, cfg.Disk.Encryption.TPM)
	return cfg.Disk.Encryption.TPM
}

// The EK certificate is required unless the config says otherwise.
func TestTPMSealConfig_AllowMissingEKCertificate_DefaultsToRequired(t *testing.T) {
	tpm := loadTPMSealConfig(t, "disk:\n  encryption:\n    tpm:\n      handle: 0x81000001\n")
	require.False(t, tpm.AllowMissingEKCertificate)
}

func TestTPMSealConfig_AllowMissingEKCertificate_Relaxed(t *testing.T) {
	tpm := loadTPMSealConfig(t, "disk:\n  encryption:\n    tpm:\n      allow-missing-ek-certificate: true\n")
	require.True(t, tpm.AllowMissingEKCertificate)
}

func TestTPMSealConfig_AllowMissingEKCertificate_NotABool(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("disk:\n  encryption:\n    tpm:\n      allow-missing-ek-certificate: [yes]\n"), 0600))
	_, err := LoadConfig(path)
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
}
