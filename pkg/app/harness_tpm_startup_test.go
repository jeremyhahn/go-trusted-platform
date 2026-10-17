package app

import (
	"context"
	"encoding/binary"
	"errors"
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
	a, err := harnessStart(t, newHarnessSwtpmState(t), t.TempDir(), harnessSOPIN)
	require.NoError(t, err)
	digest, err := a.TPM.PlatformPolicyDigest()
	require.NoError(t, err, "PCR 23 is present in the sha256 bank")
	require.NotEmpty(t, digest.Buffer)
}

// harnessSOPIN is the SO PIN run-integration-tests.sh starts platformd with
// (--raw-so-pin=123456).
const harnessSOPIN = "123456"

// errInjectedTPMFault is the transport error countingTPM injects.
var errInjectedTPMFault = errors.New("injected TPM transport fault")

// countingTPM forwards commands to a TPM, counts them by command code, and
// fails the command named by failCC. It has no Close, so an SDK TPM closing
// it at the end of one start leaves the simulator open for the next.
type countingTPM struct {
	tpm    transport.TPM
	counts map[tpm2.TPMCC]int
	failCC tpm2.TPMCC
}

func newCountingTPM(tpm transport.TPM) *countingTPM {
	return &countingTPM{tpm: tpm, counts: map[tpm2.TPMCC]int{}}
}

// Send counts the command code (TPM 2.0 Part 1 §18.2: the 10-byte command
// header ends with it) and forwards the command.
func (c *countingTPM) Send(cmd []byte) ([]byte, error) {
	cc := tpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:10]))
	c.counts[cc]++
	if c.failCC != 0 && cc == c.failCC {
		return nil, errInjectedTPMFault
	}
	return c.tpm.Send(cmd)
}

// harnessStart is one platformd start on the harness TPM, as App.Init runs
// it: a fresh App and SDK TPM with the integration config, then InitTPM and
// InitPlatformKeyStore. Starts sharing platformDir share the on-disk state.
func harnessStart(t *testing.T, tpm transport.TPM, platformDir, soPIN string) (*App, error) {
	t.Helper()
	restore := disklessCmdlinePath
	t.Cleanup(func() { disklessCmdlinePath = restore })
	disklessCmdlinePath = filepath.Join(t.TempDir(), "cmdline")
	require.NoError(t, os.WriteFile(disklessCmdlinePath, []byte("console=ttyS0\n"), 0o600))

	a := loadTemplate(t, integrationConfig)
	a.Logger = logging.DefaultLogger()
	a.PlatformDir = platformDir

	tpmDir := filepath.Join(platformDir, "tpm")
	require.NoError(t, os.MkdirAll(tpmDir, 0o700))
	storage, err := xkmssdk.NewFileStorageBackend(tpmDir)
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a.TPM, err = xkmssdk.NewTPM2(&xkmssdk.TPMParams{
		Backend:   xkmssdk.NewFileBackend(logger, storage),
		Config:    &a.TPMConfig,
		Logger:    logger,
		Transport: tpm,
	})
	require.NoError(t, err, "the persistent EK satisfies NewTPM2")
	t.Cleanup(func() { require.NoError(t, a.TPM.Close()) })

	so, user, err := a.ParsePINs([]byte(soPIN), []byte("123456"))
	require.NoError(t, err)
	if err := a.InitTPM(context.Background(), so, user, &AppInitParams{}); err != nil {
		return a, err
	}
	err = a.InitPlatformKeyStore(so, user)
	return a, err
}

// ownerAuthorizes reports whether the TPM owner hierarchy accepts auth.
func ownerAuthorizes(t *testing.T, tpm transport.TPM, auth string) error {
	t.Helper()
	pw, err := xkmssdk.NewPasswordFromString(auth)
	require.NoError(t, err)
	return verifyOwnerAuth(tpm, pw)
}

// hierarchyAuthState reads TPMA_PERMANENT from the TPM.
func hierarchyAuthState(t *testing.T, tpm transport.TPM) tpmHierarchyAuthState {
	t.Helper()
	state, err := readTPMHierarchyAuthState(tpm)
	require.NoError(t, err)
	return state
}

// TestTPMOwnership_FirstStartTakesOwnership: on a fresh EK-only TPM (empty
// owner auth, as shipped) the first start creates the Platform KeyStore SRK
// under the empty owner auth, then sets the owner auth to the SO PIN once.
// The endorsement auth is left empty.
func TestTPMOwnership_FirstStartTakesOwnership(t *testing.T) {
	sim := newHarnessSwtpmState(t)
	require.False(t, hierarchyAuthState(t, sim).ownerAuthSet, "a fresh TPM has empty owner auth")
	counting := newCountingTPM(sim)

	a, err := harnessStart(t, counting, t.TempDir(), harnessSOPIN)
	require.NoError(t, err)
	require.NotNil(t, a.PlatformKS)
	require.Equal(t, 1, counting.counts[tpm2.TPMCCHierarchyChanegAuth])

	state := hierarchyAuthState(t, sim)
	require.True(t, state.ownerAuthSet)
	require.False(t, state.endorsementAuthSet, "the endorsement auth is not changed")
	require.NoError(t, ownerAuthorizes(t, sim, harnessSOPIN))
	var rejected *OwnerAuthRejectedError
	require.ErrorAs(t, ownerAuthorizes(t, sim, ""), &rejected)
	require.Equal(t, harnessSOPIN, a.TPMConfig.SSRK.HierarchyAuth)
	require.Empty(t, a.TPMConfig.EK.HierarchyAuth)
}

// TestTPMOwnership_SecondStartUsesSOPIN: a restart on the owned TPM opens the
// Platform KeyStore with the SO PIN and does not change the owner auth again.
func TestTPMOwnership_SecondStartUsesSOPIN(t *testing.T) {
	sim := newHarnessSwtpmState(t)
	dir := t.TempDir()
	_, err := harnessStart(t, sim, dir, harnessSOPIN)
	require.NoError(t, err)

	counting := newCountingTPM(sim)
	a, err := harnessStart(t, counting, dir, harnessSOPIN)
	require.NoError(t, err)
	require.NotNil(t, a.PlatformKS)
	require.Zero(t, counting.counts[tpm2.TPMCCHierarchyChanegAuth])
	require.Equal(t, harnessSOPIN, a.TPMConfig.SSRK.HierarchyAuth)
	require.NoError(t, ownerAuthorizes(t, sim, harnessSOPIN))
}

// TestTPMOwnership_SecondStartWrongSOPIN: a restart with an SO PIN the owned
// TPM does not hold fails with OwnerAuthRejectedError.
func TestTPMOwnership_SecondStartWrongSOPIN(t *testing.T) {
	sim := newHarnessSwtpmState(t)
	dir := t.TempDir()
	_, err := harnessStart(t, sim, dir, harnessSOPIN)
	require.NoError(t, err)

	a, err := harnessStart(t, sim, dir, "654321")
	var rejected *OwnerAuthRejectedError
	require.ErrorAs(t, err, &rejected)
	require.Nil(t, a.PlatformKS)
	require.NoError(t, ownerAuthorizes(t, sim, harnessSOPIN), "the owner auth is unchanged")
}

// TestTPMOwnership_AlreadyOwnedTPM: a TPM whose owner and endorsement auth
// an earlier provisioning set to the SO PIN starts with the SO PIN for both,
// with no ownership change.
func TestTPMOwnership_AlreadyOwnedTPM(t *testing.T) {
	sim := newHarnessSwtpmState(t)
	for _, hierarchy := range []tpm2.TPMHandle{tpm2.TPMRHOwner, tpm2.TPMRHEndorsement} {
		_, err := tpm2.HierarchyChangeAuth{
			AuthHandle: hierarchy,
			NewAuth:    tpm2.TPM2BAuth{Buffer: []byte(harnessSOPIN)},
		}.Execute(sim)
		require.NoError(t, err)
	}

	counting := newCountingTPM(sim)
	a, err := harnessStart(t, counting, t.TempDir(), harnessSOPIN)
	require.NoError(t, err)
	require.NotNil(t, a.PlatformKS)
	require.Zero(t, counting.counts[tpm2.TPMCCHierarchyChanegAuth])
	require.Equal(t, harnessSOPIN, a.TPMConfig.SSRK.HierarchyAuth)
	require.Equal(t, harnessSOPIN, a.TPMConfig.EK.HierarchyAuth)
}

// TestTPMOwnership_ChangeAuthFault: a failed TPM2_HierarchyChangeAuth fails
// the start with TPMOwnershipError and leaves the TPM unowned.
func TestTPMOwnership_ChangeAuthFault(t *testing.T) {
	sim := newHarnessSwtpmState(t)
	counting := newCountingTPM(sim)
	counting.failCC = tpm2.TPMCCHierarchyChanegAuth

	_, err := harnessStart(t, counting, t.TempDir(), harnessSOPIN)
	var ownership *TPMOwnershipError
	require.ErrorAs(t, err, &ownership)
	require.ErrorIs(t, err, errInjectedTPMFault)
	require.False(t, hierarchyAuthState(t, sim).ownerAuthSet)
}

// TestReadTPMHierarchyAuthState_TransportFault: a failed TPM2_GetCapability
// is a TPMPermanentReadError, never a silent "not owned".
func TestReadTPMHierarchyAuthState_TransportFault(t *testing.T) {
	counting := newCountingTPM(newHarnessSwtpmState(t))
	counting.failCC = tpm2.TPMCCGetCapability

	_, err := readTPMHierarchyAuthState(counting)
	var readErr *TPMPermanentReadError
	require.ErrorAs(t, err, &readErr)
	require.ErrorIs(t, err, errInjectedTPMFault)
}

// TestVerifyOwnerAuth_TransportFault: a probe that fails for a reason other
// than the auth is an OwnerAuthProbeError, not a rejected SO PIN.
func TestVerifyOwnerAuth_TransportFault(t *testing.T) {
	// One simulator is open at a time, so each fault runs in its own subtest
	// and closes its simulator before the next opens.
	faults := map[string]tpm2.TPMCC{
		"StartAuthSession": tpm2.TPMCCStartAuthSession,
		"PolicySecret":     tpm2.TPMCCPolicySecret,
	}
	for name, cc := range faults {
		t.Run(name, func(t *testing.T) {
			counting := newCountingTPM(newHarnessSwtpmState(t))
			counting.failCC = cc

			err := ownerAuthorizes(t, counting, harnessSOPIN)
			var probeErr *OwnerAuthProbeError
			require.ErrorAs(t, err, &probeErr)
			var rejected *OwnerAuthRejectedError
			require.False(t, errors.As(err, &rejected))
		})
	}
}

// singleAlgorithmTPM is a TPM that implements one asymmetric algorithm: it
// refuses, as a real TPM unmarshalling an unimplemented TPMI_ALG_PUBLIC does
// (TPM 2.0 Part 2 §12.2.2, TPM_RC_TYPE), every object creation whose public
// area names the other.
type singleAlgorithmTPM struct {
	tpm     transport.TPM
	refused tpm2.TPMAlgID
}

// TPM 2.0 Part 2 §6.6.3: a format-one response code naming parameter 2, the
// inPublic of TPM2_CreatePrimary, TPM2_Create and TPM2_CreateLoaded.
const (
	rcParameterBit   = 0x040
	rcParameterTwo   = 2 << 8
	tpmSTNoSessions  = 0x8001
	tpmSTSessions    = 0x8002
	commandHeaderLen = 10
)

func (s *singleAlgorithmTPM) Send(cmd []byte) ([]byte, error) {
	if s.publicType(cmd) == s.refused {
		rsp := make([]byte, commandHeaderLen)
		binary.BigEndian.PutUint16(rsp[0:2], tpmSTNoSessions)
		binary.BigEndian.PutUint32(rsp[2:6], commandHeaderLen)
		binary.BigEndian.PutUint32(rsp[6:10], uint32(tpm2.TPMRCType)|rcParameterBit|rcParameterTwo)
		return rsp, nil
	}
	return s.tpm.Send(cmd)
}

// publicType returns the algorithm of an object-creating command's inPublic,
// or TPMAlgNull for any other command. Each of the three takes one handle,
// then the authorization area, then inSensitive and inPublic.
func (s *singleAlgorithmTPM) publicType(cmd []byte) tpm2.TPMAlgID {
	cc := tpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:10]))
	if cc != tpm2.TPMCCCreatePrimary && cc != tpm2.TPMCCCreate && cc != tpm2.TPMCCCreateLoaded {
		return tpm2.TPMAlgNull
	}
	off := commandHeaderLen + 4
	if binary.BigEndian.Uint16(cmd[0:2]) == tpmSTSessions {
		off += 4 + int(binary.BigEndian.Uint32(cmd[off:off+4]))
	}
	off += 2 + int(binary.BigEndian.Uint16(cmd[off:off+2]))
	return tpm2.TPMAlgID(binary.BigEndian.Uint16(cmd[off+2 : off+4]))
}

// ownedSingleAlgorithmTPM is a simulator whose owner auth is the SO PIN,
// fronted as a TPM without the refused algorithm.
func ownedSingleAlgorithmTPM(t *testing.T, refused tpm2.TPMAlgID) transport.TPM {
	t.Helper()
	sim := newHarnessSwtpmState(t)
	_, err := tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.TPMRHOwner,
		NewAuth:    tpm2.TPM2BAuth{Buffer: []byte(harnessSOPIN)},
	}.Execute(sim)
	require.NoError(t, err)
	return &singleAlgorithmTPM{tpm: sim, refused: refused}
}

// Codex 5468 P2: the probe must not need a key algorithm the TPM lacks. The
// filter is checked first so the test cannot pass against a TPM that still
// implements the refused algorithm.
func TestVerifyOwnerAuth_SingleAlgorithmTPM(t *testing.T) {
	cases := []struct {
		name      string
		refused   tpm2.TPMAlgID
		refusedT  tpm2.TPMTPublic
		supported tpm2.TPMTPublic
	}{
		{"RSA only", tpm2.TPMAlgECC, tpm2.ECCSRKTemplate, tpm2.RSASRKTemplate},
		{"ECC only", tpm2.TPMAlgRSA, tpm2.RSASRKTemplate, tpm2.ECCSRKTemplate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tpm := ownedSingleAlgorithmTPM(t, tc.refused)
			owner := tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth([]byte(harnessSOPIN))}

			_, err := tpm2.CreatePrimary{PrimaryHandle: owner, InPublic: tpm2.New2B(tc.refusedT)}.Execute(tpm)
			require.ErrorIs(t, err, tpm2.TPMRCType, "the TPM must lack the refused algorithm")
			rsp, err := tpm2.CreatePrimary{PrimaryHandle: owner, InPublic: tpm2.New2B(tc.supported)}.Execute(tpm)
			require.NoError(t, err, "the TPM must implement the other algorithm")
			_, err = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(tpm)
			require.NoError(t, err)

			require.NoError(t, ownerAuthorizes(t, tpm, harnessSOPIN), "the right SO PIN is accepted")

			err = ownerAuthorizes(t, tpm, "654321")
			var rejected *OwnerAuthRejectedError
			require.ErrorAs(t, err, &rejected, "a wrong SO PIN is rejected, not a probe failure")
			require.NoError(t, ownerAuthorizes(t, tpm, harnessSOPIN), "a wrong PIN costs no lockout")
		})
	}
}

// Codex 5468 P2: an RSA-configured node on a TPM without ECC provisions on
// its first start and must start again with the same SO PIN, and still
// refuse a wrong one.
func TestTPMOwnership_RestartOnTPMWithoutECC(t *testing.T) {
	tpm := &singleAlgorithmTPM{tpm: newHarnessSwtpmState(t), refused: tpm2.TPMAlgECC}
	dir := t.TempDir()
	_, err := harnessStart(t, tpm, dir, harnessSOPIN)
	require.NoError(t, err, "first start takes ownership")

	a, err := harnessStart(t, tpm, dir, harnessSOPIN)
	require.NoError(t, err, "the restart's owner-auth probe must not need ECC")
	require.NotNil(t, a.PlatformKS)

	a, err = harnessStart(t, tpm, dir, "654321")
	var rejected *OwnerAuthRejectedError
	require.ErrorAs(t, err, &rejected)
	require.Nil(t, a.PlatformKS)
}
