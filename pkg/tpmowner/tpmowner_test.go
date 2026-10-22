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
}

func (f *faultTPM) Send(cmd []byte) ([]byte, error) {
	if libtpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:10])) == f.failCC {
		return nil, errInjectedTPMFault
	}
	return f.tpm.Send(cmd)
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
	var oldAuth []byte
	if oldSecret != nil {
		oldAuth = oldSecret.Bytes()
	}
	_, err := libtpm2.HierarchyChangeAuth{
		AuthHandle: libtpm2.AuthHandle{Handle: *hierarchy, Auth: libtpm2.PasswordAuth(oldAuth)},
		NewAuth:    libtpm2.TPM2BAuth{Buffer: newSecret.Bytes()},
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

// On a fresh TPM, Establish takes ownership: the TPM leaves with the SO PIN
// as owner auth.
func TestEstablish_FreshTPM(t *testing.T) {
	tpm := newSimTPM(t)
	took, err := Establish(newModule(tpm), password(t, testSOPIN))
	require.NoError(t, err)
	require.True(t, took)

	state := authState(t, tpm)
	require.True(t, state.OwnerAuthSet)
	require.False(t, state.EndorsementAuthSet)
	require.NoError(t, VerifyOwnerAuth(tpm, password(t, testSOPIN)))
}

// On a TPM already owned by the SO PIN, Establish proves the PIN and
// presents it without changing the TPM.
func TestEstablish_AlreadyOwned(t *testing.T) {
	tpm := newSimTPM(t)
	require.NoError(t, TakeOwnership(newModule(tpm), password(t, testSOPIN)))

	m := newModule(tpm)
	took, err := Establish(m, password(t, testSOPIN))
	require.NoError(t, err)
	require.False(t, took)
	require.Equal(t, testSOPIN, m.cfg.SSRK.HierarchyAuth)
}

func TestEstablish_AlreadyOwnedWrongPIN(t *testing.T) {
	tpm := newSimTPM(t)
	require.NoError(t, TakeOwnership(newModule(tpm), password(t, testSOPIN)))

	m := newModule(tpm)
	took, err := Establish(m, password(t, "654321"))
	var rejected *OwnerAuthRejectedError
	require.ErrorAs(t, err, &rejected)
	require.False(t, took)
	require.Nil(t, m.cfg.SSRK, "a rejected SO PIN is not presented")
}

func TestEstablish_ReadFault(t *testing.T) {
	tpm := newSimTPM(t)
	took, err := Establish(newModule(&faultTPM{tpm: tpm, failCC: libtpm2.TPMCCGetCapability}), password(t, testSOPIN))
	var readErr *TPMPermanentReadError
	require.ErrorAs(t, err, &readErr)
	require.False(t, took)
	require.False(t, authState(t, tpm).OwnerAuthSet, "an unknown state takes no ownership")
}

func TestEstablish_ChangeAuthFault(t *testing.T) {
	tpm := newSimTPM(t)
	took, err := Establish(newModule(&faultTPM{tpm: tpm, failCC: libtpm2.TPMCCHierarchyChanegAuth}), password(t, testSOPIN))
	var ownership *TPMOwnershipError
	require.ErrorAs(t, err, &ownership)
	require.False(t, took)
}
