package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpmowner"
	"github.com/stretchr/testify/require"
)

const testSOPINRef = "kms://platform/so-pin?ensure=true&len=8&enc=numeric"

// copyingSecretStore copies secrets in and out, as the SDK does when it
// serializes requests and responses, so the caller may wipe its buffers.
type copyingSecretStore struct {
	*fakeSecretStore
}

// GetSecret returns a copy, as the SDK does when it deserializes the
// response, so the caller may wipe it.
func (c copyingSecretStore) GetSecret(ctx context.Context, req *baasservice.GetSecretRequest) (*baasservice.GetSecretResponse, error) {
	rsp, err := c.fakeSecretStore.GetSecret(ctx, req)
	if err != nil {
		return nil, err
	}
	copied := *rsp
	copied.Data = append([]byte(nil), rsp.Data...)
	return &copied, nil
}

func (c copyingSecretStore) StoreSecret(ctx context.Context, req *baasservice.StoreSecretRequest) (*baasservice.StoreSecretResponse, error) {
	stored := *req
	stored.Data = append([]byte(nil), req.Data...)
	return c.fakeSecretStore.StoreSecret(ctx, &stored)
}

func soPINHandoffApp(soPIN string) *App {
	return &App{
		Logger:         logging.DefaultLogger(),
		PlatformConfig: &PlatformInitConfig{SOPin: soPIN},
	}
}

// stageSOPIN writes the SO PIN firstboot would stage and returns its path.
func stageSOPIN(t *testing.T, pin string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "so-pin")
	require.NoError(t, os.WriteFile(path, []byte(pin), 0600))
	return path
}

// The staged SO PIN is stored at the reference's KMS path, where the kms://
// resolver finds it instead of generating another, and the file is shredded.
func TestConsumeSOPINHandoff_StoresAtKMSPathAndShreds(t *testing.T) {
	store := copyingSecretStore{newFakeSecretStore()}
	path := stageSOPIN(t, "12345678")

	require.NoError(t, soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), store, notConsulted(t), path))
	require.Equal(t, []byte("12345678"), store.data["platform/so-pin"])
	require.Equal(t, "firstboot-handoff", store.meta["platform/so-pin"]["source"])
	require.NoFileExists(t, path)
}

func TestConsumeSOPINHandoff_NothingStaged(t *testing.T) {
	store := newFakeSecretStore()
	path := filepath.Join(t.TempDir(), "so-pin")

	require.NoError(t, soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), store, notConsulted(t), path))
	require.Empty(t, store.writes)
}

// A literal platform.so-pin needs no KMS copy: the staged file is shredded
// and nothing is stored.
func TestConsumeSOPINHandoff_LiteralShredsWithoutStoring(t *testing.T) {
	store := newFakeSecretStore()
	path := stageSOPIN(t, "12345678")

	require.NoError(t, soPINHandoffApp("123456").consumeSOPINHandoff(context.Background(), store, notConsulted(t), path))
	require.Empty(t, store.writes)
	require.NoFileExists(t, path)
}

// A failed store keeps the staged file: shredding it would lose the owner
// auth firstboot set.
func TestConsumeSOPINHandoff_StoreFailureKeepsFile(t *testing.T) {
	store := newFakeSecretStore()
	errPut := errors.New("put refused")
	store.putErr = errPut
	path := stageSOPIN(t, "12345678")

	err := soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), store, notConsulted(t), path)
	var handoffErr *SOPINHandoffError
	require.ErrorAs(t, err, &handoffErr)
	require.ErrorIs(t, err, errPut)
	require.FileExists(t, path)
}

func TestConsumeSOPINHandoff_NoSecretStoreKeepsFile(t *testing.T) {
	path := stageSOPIN(t, "12345678")

	err := soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), nil, notConsulted(t), path)
	require.ErrorIs(t, err, ErrSOPINHandoffSecretsUnavailable)
	require.FileExists(t, path)
}

func TestConsumeSOPINHandoff_RefusedReference(t *testing.T) {
	path := stageSOPIN(t, "12345678")

	err := soPINHandoffApp("").consumeSOPINHandoff(context.Background(), newFakeSecretStore(), notConsulted(t), path)
	require.ErrorIs(t, err, tpmowner.ErrSOPINNotConfigured)
	require.FileExists(t, path)
}

func TestConsumeSOPINHandoff_Unreadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "so-pin")
	require.NoError(t, os.Mkdir(path, 0700))

	err := soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), newFakeSecretStore(), notConsulted(t), path)
	var handoffErr *SOPINHandoffError
	require.ErrorAs(t, err, &handoffErr)
}

// A firstboot retry whose staged SO PIN the TPM rejected must not replace
// the SO PIN platformd already persisted (#1012 review P1).
func TestConsumeSOPINHandoff_RejectedStagedPINKeepsPersisted(t *testing.T) {
	store := persistedSOPINStore("11111111")
	path := stageSOPIN(t, "22222222")

	require.NoError(t, soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), store, ownerAuthIs("11111111"), path))
	require.Equal(t, []byte("11111111"), store.data["platform/so-pin"], "the persisted SO PIN is unchanged")
	require.Zero(t, store.writeCount("platform/so-pin"))
	require.NoFileExists(t, path, "the rejected staged SO PIN is discarded")
}

// notConsulted is a verifier for paths that must never ask the TPM.
func notConsulted(t *testing.T) ownerAuthVerifier {
	return func(xkmssdk.Password) error {
		t.Fatal("the TPM owner auth was consulted")
		return nil
	}
}

// ownerAuthIs is a verifier for a TPM whose owner auth is ownerAuth.
func ownerAuthIs(ownerAuth string) ownerAuthVerifier {
	return func(soPIN xkmssdk.Password) error {
		if string(soPIN.Bytes()) != ownerAuth {
			return &tpmowner.OwnerAuthRejectedError{Cause: errors.New("TPM_RC_BAD_AUTH")}
		}
		return nil
	}
}

// persistedSOPINStore holds the SO PIN a previous platformd start stored.
func persistedSOPINStore(pin string) copyingSecretStore {
	store := copyingSecretStore{newFakeSecretStore()}
	store.data["platform/so-pin"] = []byte(pin)
	return store
}

// A staged SO PIN the TPM confirms as its owner auth replaces a stale
// persisted one (the TPM was cleared and firstboot took ownership again).
func TestConsumeSOPINHandoff_ConfirmedStagedPINReplacesPersisted(t *testing.T) {
	store := persistedSOPINStore("11111111")
	path := stageSOPIN(t, "22222222")

	require.NoError(t, soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), store, ownerAuthIs("22222222"), path))
	require.Equal(t, []byte("22222222"), store.data["platform/so-pin"])
	require.NoFileExists(t, path)
}

// A staged SO PIN equal to the persisted one needs neither the TPM nor a
// write.
func TestConsumeSOPINHandoff_SameAsPersistedShredsWithoutStoring(t *testing.T) {
	store := persistedSOPINStore("11111111")
	path := stageSOPIN(t, "11111111")

	require.NoError(t, soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), store, notConsulted(t), path))
	require.Zero(t, store.writeCount("platform/so-pin"))
	require.NoFileExists(t, path)
}

// On a TPM with no owner auth set firstboot did not take ownership with the
// staged PIN: the persisted one is kept.
func TestConsumeSOPINHandoff_UnownedTPMKeepsPersisted(t *testing.T) {
	store := persistedSOPINStore("11111111")
	path := stageSOPIN(t, "22222222")
	unowned := func(xkmssdk.Password) error { return ErrSOPINHandoffTPMUnowned }

	require.NoError(t, soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), store, unowned, path))
	require.Equal(t, []byte("11111111"), store.data["platform/so-pin"])
	require.NoFileExists(t, path)
}

// A TPM that cannot be asked keeps both the persisted SO PIN and the staged
// file, so the next start can decide.
func TestConsumeSOPINHandoff_VerifyFaultKeepsBoth(t *testing.T) {
	store := persistedSOPINStore("11111111")
	path := stageSOPIN(t, "22222222")
	faulty := func(xkmssdk.Password) error { return ErrSOPINHandoffNoTPM }

	err := soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), store, faulty, path)
	var handoffErr *SOPINHandoffError
	require.ErrorAs(t, err, &handoffErr)
	require.ErrorIs(t, err, ErrSOPINHandoffNoTPM)
	require.Equal(t, []byte("11111111"), store.data["platform/so-pin"])
	require.FileExists(t, path)
}

// A KMS read failure other than not-found keeps the staged file: the
// handoff cannot tell a first provision from a retry.
func TestConsumeSOPINHandoff_PersistedReadFailureKeepsFile(t *testing.T) {
	store := newFakeSecretStore()
	errGet := errors.New("kms unavailable")
	store.getErr = errGet
	path := stageSOPIN(t, "22222222")

	err := soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), store, notConsulted(t), path)
	var handoffErr *SOPINHandoffError
	require.ErrorAs(t, err, &handoffErr)
	require.ErrorIs(t, err, errGet)
	require.Zero(t, store.writeCount("platform/so-pin"))
	require.FileExists(t, path)
}

func TestConfirmStagedSOPIN_RejectionNamesReason(t *testing.T) {
	err := confirmStagedSOPIN(ownerAuthIs("11111111"), "platform/so-pin", []byte("22222222"))
	var rejected *SOPINHandoffRejectedError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, "platform/so-pin", rejected.KMSPath)
	var badAuth *tpmowner.OwnerAuthRejectedError
	require.ErrorAs(t, err, &badAuth)
	require.Contains(t, err.Error(), "the SO PIN persisted at platform/so-pin is kept")
}

func TestConfirmStagedSOPIN_Confirmed(t *testing.T) {
	require.NoError(t, confirmStagedSOPIN(ownerAuthIs("22222222"), "platform/so-pin", []byte("22222222")))
}

// verifyOwnerAuthAtHandoff asks the TPM platformd owns (swtpm harness).
func TestVerifyOwnerAuthAtHandoff_RightAndWrongPIN(t *testing.T) {
	a, err := harnessStart(t, newHarnessSwtpmState(t), t.TempDir(), harnessSOPIN)
	require.NoError(t, err)

	right, err := xkmssdk.NewPasswordFromString(harnessSOPIN)
	require.NoError(t, err)
	require.NoError(t, a.verifyOwnerAuthAtHandoff(right))

	wrong, err := xkmssdk.NewPasswordFromString("654321")
	require.NoError(t, err)
	var rejected *tpmowner.OwnerAuthRejectedError
	require.ErrorAs(t, a.verifyOwnerAuthAtHandoff(wrong), &rejected)
}
