package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpmowner"
	"github.com/stretchr/testify/require"
)

const testSOPINRef = "kms://platform/so-pin?ensure=true&len=8&enc=numeric"

// copyingSecretStore keeps a copy of each stored secret, as the SDK does when
// it serializes the request, so the caller may wipe its buffer afterwards.
type copyingSecretStore struct {
	*fakeSecretStore
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

	require.NoError(t, soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), store, path))
	require.Equal(t, []byte("12345678"), store.data["platform/so-pin"])
	require.Equal(t, "firstboot-handoff", store.meta["platform/so-pin"]["source"])
	require.NoFileExists(t, path)
}

func TestConsumeSOPINHandoff_NothingStaged(t *testing.T) {
	store := newFakeSecretStore()
	path := filepath.Join(t.TempDir(), "so-pin")

	require.NoError(t, soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), store, path))
	require.Empty(t, store.writes)
}

// A literal platform.so-pin needs no KMS copy: the staged file is shredded
// and nothing is stored.
func TestConsumeSOPINHandoff_LiteralShredsWithoutStoring(t *testing.T) {
	store := newFakeSecretStore()
	path := stageSOPIN(t, "12345678")

	require.NoError(t, soPINHandoffApp("123456").consumeSOPINHandoff(context.Background(), store, path))
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

	err := soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), store, path)
	var handoffErr *SOPINHandoffError
	require.ErrorAs(t, err, &handoffErr)
	require.ErrorIs(t, err, errPut)
	require.FileExists(t, path)
}

func TestConsumeSOPINHandoff_NoSecretStoreKeepsFile(t *testing.T) {
	path := stageSOPIN(t, "12345678")

	err := soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), nil, path)
	require.ErrorIs(t, err, ErrSOPINHandoffSecretsUnavailable)
	require.FileExists(t, path)
}

func TestConsumeSOPINHandoff_RefusedReference(t *testing.T) {
	path := stageSOPIN(t, "12345678")

	err := soPINHandoffApp("").consumeSOPINHandoff(context.Background(), newFakeSecretStore(), path)
	require.ErrorIs(t, err, tpmowner.ErrSOPINNotConfigured)
	require.FileExists(t, path)
}

func TestConsumeSOPINHandoff_Unreadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "so-pin")
	require.NoError(t, os.Mkdir(path, 0700))

	err := soPINHandoffApp(testSOPINRef).consumeSOPINHandoff(context.Background(), newFakeSecretStore(), path)
	var handoffErr *SOPINHandoffError
	require.ErrorAs(t, err, &handoffErr)
}
