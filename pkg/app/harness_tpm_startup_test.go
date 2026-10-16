package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// harnessEKHandle is where swtpm_setup --createek persists the RSA EK
// (build/docker/devcontainer/swtpm-provision.sh), and what the harness
// config's tpm.ek.handle names.
const harnessEKHandle = tpm2.TPMHandle(0x81010001)

// newHarnessSwtpmState returns a simulator TPM carrying what the harness
// swtpm carries when platformd starts: a persistent RSA EK at 0x81010001,
// empty hierarchy auth, and no SRK.
func newHarnessSwtpmState(t *testing.T) transport.TPM {
	t.Helper()

	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sim.Close()) })
	tpm := transport.FromReadWriter(sim)

	ek, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(tpm)
	require.NoError(t, err)
	_, err = tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     &tpm2.NamedHandle{Handle: ek.ObjectHandle, Name: ek.Name},
		PersistentHandle: harnessEKHandle,
	}.Execute(tpm)
	require.NoError(t, err)
	_, err = tpm2.FlushContext{FlushHandle: ek.ObjectHandle}.Execute(tpm)
	require.NoError(t, err)
	return tpm
}

// TestHarnessTPMStartup_EKOnlyInitTPM runs platformd's InitTPM (App.Init)
// with the integration config's tpm section on a TPM holding only the
// harness EK: the EK satisfies OpenTPM without provisioning, and the
// platform policy digest over PCR 23 in the sha256 bank — where main's
// Integration job failed on the runner's hardware TPM — is computable.
func TestHarnessTPMStartup_EKOnlyInitTPM(t *testing.T) {
	restore := disklessCmdlinePath
	t.Cleanup(func() { disklessCmdlinePath = restore })
	disklessCmdlinePath = filepath.Join(t.TempDir(), "cmdline")
	require.NoError(t, os.WriteFile(disklessCmdlinePath, []byte("console=ttyS0\n"), 0o600))

	a := loadTemplate(t, integrationConfig)
	a.Logger = logging.DefaultLogger()
	a.PlatformDir = t.TempDir()

	storage, err := xkmssdk.NewFileStorageBackend(t.TempDir())
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a.TPM, err = xkmssdk.NewTPM2(&xkmssdk.TPMParams{
		Backend:   xkmssdk.NewFileBackend(logger, storage),
		Config:    &a.TPMConfig,
		Logger:    logger,
		Transport: newHarnessSwtpmState(t),
	})
	require.NoError(t, err, "the persistent EK satisfies NewTPM2")
	t.Cleanup(func() { require.NoError(t, a.TPM.Close()) })

	// run-integration-tests.sh starts platformd with --raw-so-pin=123456.
	soPIN, userPIN, err := a.ParsePINs([]byte("123456"), []byte("123456"))
	require.NoError(t, err)
	// App.Init mirrors the SO PIN into the hierarchy auth (app.go:741).
	a.TPMConfig.SSRK.HierarchyAuth = string(soPIN.Bytes())
	a.TPMConfig.EK.HierarchyAuth = string(soPIN.Bytes())

	require.NoError(t, a.InitTPM(context.Background(), soPIN, userPIN, &AppInitParams{}))
	digest, err := a.TPM.PlatformPolicyDigest()
	require.NoError(t, err, "PCR 23 is present in the sha256 bank")
	require.NotEmpty(t, digest.Buffer)
}
