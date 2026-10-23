package kvstore

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errorQueryStorage is a storage where Query always returns an error,
// forcing DAOs to fall back to scan paths.
type errorQueryStorage struct {
	memoryStorage
}

func newErrorQueryStorage() *errorQueryStorage {
	return &errorQueryStorage{
		memoryStorage: *newMemoryStorage(),
	}
}

func (s *errorQueryStorage) Query(ctx context.Context, entityType, indexField string, value []byte, shardID uint64) ([]*service.Entity, error) {
	return nil, errors.New("query not supported")
}

// --- InvitationDAO tests ---

func TestInvitationDAO_GetByToken(t *testing.T) {
	t.Run("finds invitation by token via scan", func(t *testing.T) {
		storage := newErrorQueryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewInvitationDAO(storage, logger)
		ctx := context.Background()

		inv, err := entities.NewInvitation("tenant-1", "user@test.com", "member", 1, 24*time.Hour, time.Now())
		require.NoError(t, err)

		require.NoError(t, dao.Save(ctx, inv))

		found, err := dao.GetByToken(ctx, inv.Token)
		require.NoError(t, err)
		assert.Equal(t, inv.Token, found.Token)
		assert.Equal(t, "user@test.com", found.Email)
	})

	t.Run("returns error when token not found", func(t *testing.T) {
		storage := newErrorQueryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewInvitationDAO(storage, logger)
		ctx := context.Background()

		_, err := dao.GetByToken(ctx, "nonexistent-token")
		require.Error(t, err)

		var notFound ErrNotFoundByIndex
		assert.True(t, errors.As(err, &notFound))
		assert.Equal(t, "Token", notFound.IndexField)
	})

	t.Run("finds via query when index available", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewInvitationDAO(storage, logger)
		ctx := context.Background()

		inv, err := entities.NewInvitation("tenant-1", "indexed@test.com", "member", 1, 24*time.Hour, time.Now())
		require.NoError(t, err)
		require.NoError(t, dao.Save(ctx, inv))

		// memoryStorage Query returns all entities, so it will find the invitation
		found, err := dao.GetByToken(ctx, inv.Token)
		require.NoError(t, err)
		assert.Equal(t, inv.Token, found.Token)
	})
}

func TestInvitationDAO_GetByEmail(t *testing.T) {
	t.Run("finds invitation by email via scan", func(t *testing.T) {
		storage := newErrorQueryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewInvitationDAO(storage, logger)
		ctx := context.Background()

		inv, err := entities.NewInvitation("tenant-1", "find@test.com", "admin", 1, 24*time.Hour, time.Now())
		require.NoError(t, err)

		require.NoError(t, dao.Save(ctx, inv))

		found, err := dao.GetByEmail(ctx, "find@test.com")
		require.NoError(t, err)
		assert.Equal(t, "find@test.com", found.Email)
	})

	t.Run("returns error when email not found", func(t *testing.T) {
		storage := newErrorQueryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewInvitationDAO(storage, logger)
		ctx := context.Background()

		_, err := dao.GetByEmail(ctx, "missing@test.com")
		require.Error(t, err)

		var notFound ErrNotFoundByIndex
		assert.True(t, errors.As(err, &notFound))
		assert.Equal(t, "Email", notFound.IndexField)
	})

	t.Run("finds via query when index available", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewInvitationDAO(storage, logger)
		ctx := context.Background()

		inv, err := entities.NewInvitation("tenant-1", "query@test.com", "member", 1, 24*time.Hour, time.Now())
		require.NoError(t, err)
		require.NoError(t, dao.Save(ctx, inv))

		found, err := dao.GetByEmail(ctx, "query@test.com")
		require.NoError(t, err)
		assert.Equal(t, "query@test.com", found.Email)
	})
}

func TestInvitationDAO_GetByTenant(t *testing.T) {
	t.Run("returns invitations for tenant", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewInvitationDAO(storage, logger)
		ctx := context.Background()

		inv1, err := entities.NewInvitation("tenant-A", "a@test.com", "member", 1, 24*time.Hour, time.Now())
		require.NoError(t, err)
		require.NoError(t, dao.Save(ctx, inv1))

		inv2, err := entities.NewInvitation("tenant-A", "b@test.com", "admin", 1, 24*time.Hour, time.Now())
		require.NoError(t, err)
		require.NoError(t, dao.Save(ctx, inv2))

		inv3, err := entities.NewInvitation("tenant-B", "c@test.com", "member", 1, 24*time.Hour, time.Now())
		require.NoError(t, err)
		require.NoError(t, dao.Save(ctx, inv3))

		results, err := dao.GetByTenant(ctx, "tenant-A")
		require.NoError(t, err)
		assert.Len(t, results, 2)
	})

	t.Run("returns empty for unknown tenant", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewInvitationDAO(storage, logger)
		ctx := context.Background()

		results, err := dao.GetByTenant(ctx, "unknown")
		require.NoError(t, err)
		assert.Empty(t, results)
	})
}

func TestInvitationDAO_GetPendingByTenant(t *testing.T) {
	t.Run("returns only pending invitations", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewInvitationDAO(storage, logger)
		ctx := context.Background()

		// Create pending invitation
		inv1, err := entities.NewInvitation("tenant-1", "pending@test.com", "member", 1, 24*time.Hour, time.Now())
		require.NoError(t, err)
		require.NoError(t, dao.Save(ctx, inv1))

		// Create accepted invitation
		inv2, err := entities.NewInvitation("tenant-1", "accepted@test.com", "member", 1, 24*time.Hour, time.Now())
		require.NoError(t, err)
		inv2.Accept(time.Now())
		require.NoError(t, dao.Save(ctx, inv2))

		results, err := dao.GetPendingByTenant(ctx, "tenant-1")
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, entities.InvitationStatusPending, results[0].Status)
	})

	t.Run("returns empty when no pending invitations", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewInvitationDAO(storage, logger)
		ctx := context.Background()

		results, err := dao.GetPendingByTenant(ctx, "tenant-1")
		require.NoError(t, err)
		assert.Empty(t, results)
	})
}

func TestInvitationDAO_GetByToken_DeserializationError(t *testing.T) {
	storage := newErrorQueryStorage()
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.DefaultLogger()

	dao := NewInvitationDAO(storage, logger)
	ctx := context.Background()

	// Store invalid JSON - the scan should skip it and return not found
	require.NoError(t, storage.Put(ctx, entityTypeInvitation, 123, []byte("{bad"), 0))

	_, err := dao.GetByToken(ctx, "any-token")
	require.Error(t, err)
}

func TestInvitationDAO_GetByEmail_DeserializationError(t *testing.T) {
	storage := newErrorQueryStorage()
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.DefaultLogger()

	dao := NewInvitationDAO(storage, logger)
	ctx := context.Background()

	// Store invalid JSON - the scan should skip it and return not found
	require.NoError(t, storage.Put(ctx, entityTypeInvitation, 123, []byte("{bad"), 0))

	_, err := dao.GetByEmail(ctx, "any@email.com")
	require.Error(t, err)
}

func TestInvitationDAO_GetByTenant_DeserializationError(t *testing.T) {
	storage := newMemoryStorage()
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.DefaultLogger()

	dao := NewInvitationDAO(storage, logger)
	ctx := context.Background()

	// Store invalid JSON - should be skipped
	require.NoError(t, storage.Put(ctx, entityTypeInvitation, 123, []byte("{bad"), 0))

	// Also store a valid one for the tenant
	inv, err := entities.NewInvitation("t1", "ok@test.com", "member", 1, 24*time.Hour, time.Now())
	require.NoError(t, err)
	invData, err := json.Marshal(inv)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entityTypeInvitation, inv.EntityID(), invData, 0))

	results, err := dao.GetByTenant(ctx, "t1")
	require.NoError(t, err)
	assert.Len(t, results, 1)
}

func TestInvitationDAO_GetPendingByTenant_DeserializationError(t *testing.T) {
	storage := newMemoryStorage()
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.DefaultLogger()

	dao := NewInvitationDAO(storage, logger)
	ctx := context.Background()

	// Store invalid JSON - should be skipped
	require.NoError(t, storage.Put(ctx, entityTypeInvitation, 123, []byte("{bad"), 0))

	results, err := dao.GetPendingByTenant(ctx, "any")
	require.NoError(t, err)
	assert.Empty(t, results)
}

// --- RoleDAO tests ---

func TestRoleDAO_GetByName(t *testing.T) {
	t.Run("finds role by name via query", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewRoleDAO(storage, logger)
		ctx := context.Background()

		role := entities.NewRole("admin")
		require.NoError(t, dao.Save(ctx, role))

		found, err := dao.GetByName(ctx, "admin")
		require.NoError(t, err)
		assert.Equal(t, "admin", found.Name)
	})

	t.Run("finds role by name via scan fallback", func(t *testing.T) {
		storage := newErrorQueryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewRoleDAO(storage, logger)
		ctx := context.Background()

		role := entities.NewRole("editor")
		require.NoError(t, dao.Save(ctx, role))

		found, err := dao.GetByName(ctx, "editor")
		require.NoError(t, err)
		assert.Equal(t, "editor", found.Name)
	})

	t.Run("returns error when role not found", func(t *testing.T) {
		storage := newErrorQueryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewRoleDAO(storage, logger)
		ctx := context.Background()

		_, err := dao.GetByName(ctx, "nonexistent")
		require.Error(t, err)

		var notFound ErrNotFoundByIndex
		assert.True(t, errors.As(err, &notFound))
		assert.Equal(t, "Name", notFound.IndexField)
	})

	t.Run("skips corrupt role data during scan", func(t *testing.T) {
		storage := newErrorQueryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewRoleDAO(storage, logger)
		ctx := context.Background()

		// Store corrupt data
		require.NoError(t, storage.Put(ctx, entityTypeRole, 555, []byte("{bad"), 0))

		// Store valid role
		role := entities.NewRole("editor")
		require.NoError(t, dao.Save(ctx, role))

		found, err := dao.GetByName(ctx, "editor")
		require.NoError(t, err)
		assert.Equal(t, "editor", found.Name)
	})

	t.Run("query returns results but deserialization fails", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewRoleDAO(storage, logger)
		ctx := context.Background()

		// Store only corrupt data so Query returns it
		require.NoError(t, storage.Put(ctx, entityTypeRole, 555, []byte("{bad"), 0))

		_, err := dao.GetByName(ctx, "nonexistent")
		require.Error(t, err)

		var deserErr ErrDeserializationFailed
		assert.True(t, errors.As(err, &deserErr))
	})
}

// --- UserDAO tests ---

func TestUserDAO_SaveAndGet(t *testing.T) {
	storage := newMemoryStorage()
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.DefaultLogger()

	dao := NewUserDAO(storage, logger)
	ctx := context.Background()

	user := entities.NewUser("test@example.com")
	user.DisplayName = "Test User"
	require.NoError(t, dao.Save(ctx, user))

	got, err := dao.Get(ctx, user.EntityID())
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", got.Email)
	assert.Equal(t, "Test User", got.DisplayName)
}

// --- RegistrationDAO tests ---

func TestRegistrationDAO_SaveAndGet(t *testing.T) {
	storage := newMemoryStorage()
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.DefaultLogger()

	dao := NewRegistrationDAO(storage, logger)
	ctx := context.Background()

	reg := entities.NewRegistration("test@example.com")
	reg.Password = "hashed"
	require.NoError(t, dao.Save(ctx, reg))

	got, err := dao.Get(ctx, reg.EntityID())
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", got.Email)
	assert.Equal(t, "hashed", got.Password)
}

// --- WebAuthnDAO tests ---

func TestWebAuthnDAO_SaveAndGet(t *testing.T) {
	storage := newMemoryStorage()
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.DefaultLogger()

	dao := NewWebAuthnDAO(storage, logger)
	ctx := context.Background()

	blob := entities.NewBlob(12345, []byte("webauthn-session-data"))
	require.NoError(t, dao.Save(ctx, blob))

	got, err := dao.Get(ctx, blob.EntityID())
	require.NoError(t, err)
	assert.Equal(t, []byte("webauthn-session-data"), got.Bytes)
}
