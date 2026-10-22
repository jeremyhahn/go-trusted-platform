package tpmowner

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	libtpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/require"
)

const testSOPIN = "123456"

// errInjectedTPMFault is the transport error faultTPM injects.
var errInjectedTPMFault = errors.New("injected TPM transport fault")

// faultTPM forwards commands to a TPM and fails the command named by failCC.
type faultTPM struct {
	tpm    transport.TPM
	failCC libtpm2.TPMCC
	// loseResponse delivers failCC to the TPM and fails only the response,
	// as a transport that drops the reply does.
	loseResponse bool
}

func (f *faultTPM) Send(cmd []byte) ([]byte, error) {
	if libtpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:10])) != f.failCC {
		return f.tpm.Send(cmd)
	}
	if f.loseResponse {
		if _, err := f.tpm.Send(cmd); err != nil {
			return nil, err
		}
	}
	return nil, errInjectedTPMFault
}

// simModule is the Module surface over a TPM transport: SetHierarchyAuth is
// the TPM2_HierarchyChangeAuth the SDK TPM issues, authorized by the old
// secret.
type simModule struct {
	tpm transport.TPM
	cfg *xkmssdk.TPMConfig
}

func (m *simModule) Transport() transport.TPM   { return m.tpm }
func (m *simModule) Config() *xkmssdk.TPMConfig { return m.cfg }

func (m *simModule) SetHierarchyAuth(oldSecret, newSecret xkmssdk.Password, hierarchy *libtpm2.TPMHandle) error {
	var oldAuth, newAuth []byte
	if oldSecret != nil {
		oldAuth = oldSecret.Bytes()
	}
	if newSecret != nil {
		newAuth = newSecret.Bytes()
	}
	_, err := libtpm2.HierarchyChangeAuth{
		AuthHandle: libtpm2.AuthHandle{Handle: *hierarchy, Auth: libtpm2.PasswordAuth(oldAuth)},
		NewAuth:    libtpm2.TPM2BAuth{Buffer: newAuth},
	}.Execute(m.tpm)
	return err
}

// newSimTPM returns a fresh simulator TPM: empty owner, endorsement and
// lockout auth, as a TPM ships.
func newSimTPM(t *testing.T) transport.TPM {
	t.Helper()
	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sim.Close()) })
	return transport.FromReadWriter(sim)
}

func newModule(tpm transport.TPM) *simModule {
	return &simModule{tpm: tpm, cfg: &xkmssdk.TPMConfig{}}
}

func password(t *testing.T, pin string) xkmssdk.Password {
	t.Helper()
	pw, err := xkmssdk.NewPasswordFromString(pin)
	require.NoError(t, err)
	return pw
}

func authState(t *testing.T, tpm transport.TPM) HierarchyAuthState {
	t.Helper()
	state, err := ReadHierarchyAuthState(tpm)
	require.NoError(t, err)
	return state
}

func TestReadHierarchyAuthState_FreshTPM(t *testing.T) {
	require.Equal(t, HierarchyAuthState{}, authState(t, newSimTPM(t)), "a fresh TPM has empty hierarchy auth")
}

// A failed TPM2_GetCapability is a TPMPermanentReadError, never a silent
// "not owned".
func TestReadHierarchyAuthState_TransportFault(t *testing.T) {
	_, err := ReadHierarchyAuthState(&faultTPM{tpm: newSimTPM(t), failCC: libtpm2.TPMCCGetCapability})
	var readErr *TPMPermanentReadError
	require.ErrorAs(t, err, &readErr)
	require.ErrorIs(t, err, errInjectedTPMFault)
}

func TestVerifyOwnerAuth_RightAndWrongPIN(t *testing.T) {
	tpm := newSimTPM(t)
	require.NoError(t, TakeOwnership(newModule(tpm), password(t, testSOPIN)))

	require.NoError(t, VerifyOwnerAuth(tpm, password(t, testSOPIN)))

	err := VerifyOwnerAuth(tpm, password(t, "654321"))
	var rejected *OwnerAuthRejectedError
	require.ErrorAs(t, err, &rejected)
	require.ErrorIs(t, err, libtpm2.TPMRCBadAuth)
}

// A probe that fails for a reason other than the auth is an
// OwnerAuthProbeError, not a rejected SO PIN.
func TestVerifyOwnerAuth_TransportFault(t *testing.T) {
	err := VerifyOwnerAuth(&faultTPM{tpm: newSimTPM(t), failCC: libtpm2.TPMCCCreatePrimary}, password(t, testSOPIN))
	var probeErr *OwnerAuthProbeError
	require.ErrorAs(t, err, &probeErr)
	var rejected *OwnerAuthRejectedError
	require.False(t, errors.As(err, &rejected))
}

// A FlushContext whose response is lost is a probe failure, not a rejected
// SO PIN, and the probe key it created is still flushed from the TPM.
func TestVerifyOwnerAuth_FlushFault(t *testing.T) {
	tpm := newSimTPM(t)
	require.NoError(t, TakeOwnership(newModule(tpm), password(t, testSOPIN)))

	err := VerifyOwnerAuth(&faultTPM{tpm: tpm, failCC: libtpm2.TPMCCFlushContext, loseResponse: true}, password(t, testSOPIN))
	var probeErr *OwnerAuthProbeError
	require.ErrorAs(t, err, &probeErr)
	require.ErrorIs(t, err, errInjectedTPMFault)
	var rejected *OwnerAuthRejectedError
	require.False(t, errors.As(err, &rejected))

	require.Empty(t, transientHandles(t, tpm))
}

// transientHandles lists the transient objects loaded in the TPM.
func transientHandles(t *testing.T, tpm transport.TPM) []libtpm2.TPMHandle {
	t.Helper()
	rsp, err := libtpm2.GetCapability{
		Capability:    libtpm2.TPMCapHandles,
		Property:      uint32(libtpm2.TPMHTTransient) << 24,
		PropertyCount: 8,
	}.Execute(tpm)
	require.NoError(t, err)
	handles, err := rsp.CapabilityData.Data.Handles()
	require.NoError(t, err)
	return handles.Handle
}

// TakeOwnership changes the owner auth only, and presents it through the
// config.
func TestTakeOwnership_OwnerOnly(t *testing.T) {
	tpm := newSimTPM(t)
	m := newModule(tpm)
	require.NoError(t, TakeOwnership(m, password(t, testSOPIN)))

	state := authState(t, tpm)
	require.True(t, state.OwnerAuthSet)
	require.False(t, state.EndorsementAuthSet, "the endorsement auth is not changed")
	require.Equal(t, testSOPIN, m.cfg.SSRK.HierarchyAuth)
}

func TestTakeOwnership_ChangeAuthFault(t *testing.T) {
	tpm := newSimTPM(t)
	m := newModule(&faultTPM{tpm: tpm, failCC: libtpm2.TPMCCHierarchyChanegAuth})

	err := TakeOwnership(m, password(t, testSOPIN))
	var ownership *TPMOwnershipError
	require.ErrorAs(t, err, &ownership)
	require.ErrorIs(t, err, errInjectedTPMFault)
	require.False(t, authState(t, tpm).OwnerAuthSet)
	require.Nil(t, m.cfg.SSRK, "a failed change presents no owner auth")
}

// createOwnerKey creates and flushes a primary key under the empty owner
// auth, as Install and the Platform KeyStore do; it fails on an owned TPM.
func createOwnerKey(tpm transport.TPM) error {
	rsp, err := libtpm2.CreatePrimary{
		PrimaryHandle: libtpm2.AuthHandle{Handle: libtpm2.TPMRHOwner, Auth: libtpm2.PasswordAuth(nil)},
		InPublic:      libtpm2.New2B(libtpm2.ECCSRKTemplate),
	}.Execute(tpm)
	if err != nil {
		return err
	}
	_, err = libtpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(tpm)
	return err
}

// On a fresh TPM, Prepare changes nothing; keys created next under the empty
// auth, then TakeOwnership, leave the TPM owned by the SO PIN.
func TestPrepare_FreshTPM(t *testing.T) {
	tpm := newSimTPM(t)
	m := newModule(tpm)
	require.NoError(t, Prepare(m, password(t, testSOPIN)))
	require.False(t, authState(t, tpm).OwnerAuthSet)
	require.NoError(t, createOwnerKey(tpm))

	require.NoError(t, TakeOwnership(m, password(t, testSOPIN)))
	state := authState(t, tpm)
	require.True(t, state.OwnerAuthSet)
	require.False(t, state.EndorsementAuthSet)
	require.NoError(t, VerifyOwnerAuth(tpm, password(t, testSOPIN)))
}

// On a TPM already owned by the SO PIN, Prepare proves the PIN and returns
// the owner auth to empty, so the keys are recreated as on a fresh TPM and
// ownership is taken again with the same PIN.
func TestPrepare_AlreadyOwned(t *testing.T) {
	tpm := newSimTPM(t)
	m := newModule(tpm)
	require.NoError(t, TakeOwnership(m, password(t, testSOPIN)))
	require.Error(t, createOwnerKey(tpm), "an owned TPM refuses the empty owner auth")

	require.NoError(t, Prepare(m, password(t, testSOPIN)))
	require.False(t, authState(t, tpm).OwnerAuthSet)
	require.Empty(t, m.cfg.SSRK.HierarchyAuth, "the released owner auth is presented as empty")
	require.NoError(t, createOwnerKey(tpm))

	require.NoError(t, TakeOwnership(m, password(t, testSOPIN)))
	require.NoError(t, VerifyOwnerAuth(tpm, password(t, testSOPIN)))
}

// A wrong SO PIN on an owned TPM is refused and the TPM keeps its owner.
func TestPrepare_AlreadyOwnedWrongPIN(t *testing.T) {
	tpm := newSimTPM(t)
	require.NoError(t, TakeOwnership(newModule(tpm), password(t, testSOPIN)))

	err := Prepare(newModule(tpm), password(t, "654321"))
	var rejected *OwnerAuthRejectedError
	require.ErrorAs(t, err, &rejected)
	require.True(t, authState(t, tpm).OwnerAuthSet)
	require.NoError(t, VerifyOwnerAuth(tpm, password(t, testSOPIN)))
}

func TestPrepare_ReadFault(t *testing.T) {
	err := Prepare(newModule(&faultTPM{tpm: newSimTPM(t), failCC: libtpm2.TPMCCGetCapability}), password(t, testSOPIN))
	var readErr *TPMPermanentReadError
	require.ErrorAs(t, err, &readErr)
}

// A failed release is an OwnerAuthReleaseError and leaves the TPM owned.
func TestPrepare_ReleaseFault(t *testing.T) {
	tpm := newSimTPM(t)
	require.NoError(t, TakeOwnership(newModule(tpm), password(t, testSOPIN)))

	err := Prepare(newModule(&faultTPM{tpm: tpm, failCC: libtpm2.TPMCCHierarchyChanegAuth}), password(t, testSOPIN))
	var release *OwnerAuthReleaseError
	require.ErrorAs(t, err, &release)
	require.ErrorIs(t, err, errInjectedTPMFault)
	require.True(t, authState(t, tpm).OwnerAuthSet)
}
