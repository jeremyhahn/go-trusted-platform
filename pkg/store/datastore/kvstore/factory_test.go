package kvstore

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFactory(t *testing.T) {
	storage := newMemoryStorage()
	logger := logging.DefaultLogger()

	factory := NewFactory(storage, logger)
	require.NotNil(t, factory)
	assert.False(t, factory.IsClosed())
}

func TestFactory_StartStop(t *testing.T) {
	t.Run("start and stop lifecycle", func(t *testing.T) {
		storage := newMemoryStorage()
		logger := logging.DefaultLogger()
		factory := NewFactory(storage, logger)

		ctx := context.Background()

		assert.False(t, factory.IsStarted())

		err := factory.Start(ctx)
		require.NoError(t, err)
		assert.True(t, factory.IsStarted())
		assert.False(t, factory.IsClosed())

		err = factory.Stop(ctx)
		require.NoError(t, err)
		assert.True(t, factory.IsClosed())
		assert.False(t, factory.IsStarted())
	})

	t.Run("start after close returns error", func(t *testing.T) {
		storage := newMemoryStorage()
		logger := logging.DefaultLogger()
		factory := NewFactory(storage, logger)

		ctx := context.Background()
		require.NoError(t, factory.Start(ctx))
		require.NoError(t, factory.Stop(ctx))

		err := factory.Start(ctx)
		require.Error(t, err)

		var closedErr ErrFactoryClosed
		assert.True(t, errors.As(err, &closedErr))
	})

	t.Run("double stop is idempotent", func(t *testing.T) {
		storage := newMemoryStorage()
		logger := logging.DefaultLogger()
		factory := NewFactory(storage, logger)

		ctx := context.Background()
		require.NoError(t, factory.Start(ctx))
		require.NoError(t, factory.Stop(ctx))

		// Second stop should not error
		err := factory.Stop(ctx)
		require.NoError(t, err)
	})
}

func TestFactory_UserDAO(t *testing.T) {
	t.Run("returns DAO successfully", func(t *testing.T) {
		storage := newMemoryStorage()
		logger := logging.DefaultLogger()
		factory := NewFactory(storage, logger)

		dao, err := factory.UserDAO()
		require.NoError(t, err)
		require.NotNil(t, dao)

		dao2, err := factory.UserDAO()
		require.NoError(t, err)
		assert.Equal(t, dao, dao2)
	})

	t.Run("returns error when closed", func(t *testing.T) {
		storage := newMemoryStorage()
		logger := logging.DefaultLogger()
		factory := NewFactory(storage, logger)

		ctx := context.Background()
		require.NoError(t, factory.Start(ctx))
		require.NoError(t, factory.Stop(ctx))

		_, err := factory.UserDAO()
		require.Error(t, err)
	})
}

func TestFactory_RegistrationDAO(t *testing.T) {
	t.Run("returns DAO successfully", func(t *testing.T) {
		storage := newMemoryStorage()
		logger := logging.DefaultLogger()
		factory := NewFactory(storage, logger)

		dao, err := factory.RegistrationDAO()
		require.NoError(t, err)
		require.NotNil(t, dao)

		dao2, err := factory.RegistrationDAO()
		require.NoError(t, err)
		assert.Equal(t, dao, dao2)
	})

	t.Run("returns error when closed", func(t *testing.T) {
		storage := newMemoryStorage()
		logger := logging.DefaultLogger()
		factory := NewFactory(storage, logger)

		ctx := context.Background()
		require.NoError(t, factory.Start(ctx))
		require.NoError(t, factory.Stop(ctx))

		_, err := factory.RegistrationDAO()
		require.Error(t, err)
	})
}

func TestFactory_InvitationDAO(t *testing.T) {
	t.Run("returns DAO successfully", func(t *testing.T) {
		storage := newMemoryStorage()
		logger := logging.DefaultLogger()
		factory := NewFactory(storage, logger)

		dao, err := factory.InvitationDAO()
		require.NoError(t, err)
		require.NotNil(t, dao)

		dao2, err := factory.InvitationDAO()
		require.NoError(t, err)
		assert.Equal(t, dao, dao2)
	})

	t.Run("returns error when closed", func(t *testing.T) {
		storage := newMemoryStorage()
		logger := logging.DefaultLogger()
		factory := NewFactory(storage, logger)

		ctx := context.Background()
		require.NoError(t, factory.Start(ctx))
		require.NoError(t, factory.Stop(ctx))

		_, err := factory.InvitationDAO()
		require.Error(t, err)
	})
}

func TestFactory_RoleDAO(t *testing.T) {
	t.Run("returns DAO successfully", func(t *testing.T) {
		storage := newMemoryStorage()
		logger := logging.DefaultLogger()
		factory := NewFactory(storage, logger)

		dao, err := factory.RoleDAO()
		require.NoError(t, err)
		require.NotNil(t, dao)

		dao2, err := factory.RoleDAO()
		require.NoError(t, err)
		assert.Equal(t, dao, dao2)
	})

	t.Run("returns error when closed", func(t *testing.T) {
		storage := newMemoryStorage()
		logger := logging.DefaultLogger()
		factory := NewFactory(storage, logger)

		ctx := context.Background()
		require.NoError(t, factory.Start(ctx))
		require.NoError(t, factory.Stop(ctx))

		_, err := factory.RoleDAO()
		require.Error(t, err)
	})
}

func TestFactory_WebAuthnDAO(t *testing.T) {
	t.Run("returns DAO successfully", func(t *testing.T) {
		storage := newMemoryStorage()
		logger := logging.DefaultLogger()
		factory := NewFactory(storage, logger)

		dao, err := factory.WebAuthnDAO()
		require.NoError(t, err)
		require.NotNil(t, dao)

		dao2, err := factory.WebAuthnDAO()
		require.NoError(t, err)
		assert.Equal(t, dao, dao2)
	})

	t.Run("returns error when closed", func(t *testing.T) {
		storage := newMemoryStorage()
		logger := logging.DefaultLogger()
		factory := NewFactory(storage, logger)

		ctx := context.Background()
		require.NoError(t, factory.Start(ctx))
		require.NoError(t, factory.Stop(ctx))

		_, err := factory.WebAuthnDAO()
		require.Error(t, err)
	})
}

func TestFactory_SerializerType(t *testing.T) {
	storage := newMemoryStorage()
	logger := logging.DefaultLogger()
	factory := NewFactory(storage, logger)

	assert.Equal(t, serializer.SERIALIZER_JSON, factory.SerializerType())
}

func TestFactory_Storage(t *testing.T) {
	storage := newMemoryStorage()
	logger := logging.DefaultLogger()
	factory := NewFactory(storage, logger)

	assert.Equal(t, storage, factory.Storage())
}
