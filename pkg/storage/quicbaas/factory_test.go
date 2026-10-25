//go:build raft

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package quicbaas

import (
	"context"
	"sync"
	"testing"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestFactory(t *testing.T) (*Factory, func()) {
	t.Helper()

	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	err = factory.Start(context.Background())
	require.NoError(t, err)

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		factory.Stop(ctx)
	}

	return factory, cleanup
}

func TestNewFactory_Success(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)
	assert.NotNil(t, factory)
	assert.NotNil(t, factory.Client())
	assert.False(t, factory.IsStarted())
	assert.False(t, factory.IsClosed())
}

func TestNewFactory_InvalidConfig(t *testing.T) {
	cfg := &Config{} // Empty invalid config
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.Error(t, err)
	assert.Nil(t, factory)
}

func TestFactory_StartStop(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	assert.False(t, factory.IsStarted())
	assert.False(t, factory.IsClosed())

	// Start
	err = factory.Start(context.Background())
	require.NoError(t, err)

	assert.True(t, factory.IsStarted())
	assert.False(t, factory.IsClosed())

	// Stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = factory.Stop(ctx)
	cancel()
	require.NoError(t, err)

	assert.True(t, factory.IsClosed())
}

func TestFactory_Stop_Idempotent(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	cleanup() // First stop

	// Second stop should be a no-op
	ctx := context.Background()
	err := factory.Stop(ctx)
	require.NoError(t, err)

	// Third stop should also be a no-op
	err = factory.Stop(ctx)
	require.NoError(t, err)

	assert.True(t, factory.IsClosed())
}

// TestFactory_SDK_FollowsLifecycle asserts the factory hands out a working
// SDK client only between Start and Stop.
func TestFactory_SDK_FollowsLifecycle(t *testing.T) {
	factory, err := NewFactory(TestConfig(t), logging.DefaultLogger(), nil)
	require.NoError(t, err)
	assert.Nil(t, factory.SDK(), "SDK must be nil before Start")

	require.NoError(t, factory.Start(context.Background()))

	sdk := factory.SDK()
	require.NotNil(t, sdk, "SDK must be available after Start")
	require.NoError(t, sdk.Health().Ping(context.Background()))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, factory.Stop(ctx))

	assert.Nil(t, factory.SDK(), "SDK must be nil after Stop")
}

// TestFactory_Start_AfterStopReturnsErrFactoryClosed asserts a stopped
// factory cannot be restarted.
func TestFactory_Start_AfterStopReturnsErrFactoryClosed(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	cleanup()

	err := factory.Start(context.Background())

	var target ErrFactoryClosed
	assert.ErrorAs(t, err, &target)
	assert.False(t, factory.IsStarted())
}

// TestFactory_Start_ServesEveryStorageBackend asserts the embedded factory
// starts and serves KV on each storage backend its test configs select.
func TestFactory_Start_ServesEveryStorageBackend(t *testing.T) {
	tests := []struct {
		name   string
		config func(t TestingT) *Config
	}{
		{name: "Pebble", config: TestConfig},
		{name: "Memory", config: MemoryTestConfig},
		{name: "File", config: FileTestConfig},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			factory, err := NewFactory(tc.config(t), logging.DefaultLogger(), nil)
			require.NoError(t, err)
			require.NoError(t, factory.Start(context.Background()))
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				require.NoError(t, factory.Stop(ctx))
			}()

			sdk := factory.SDK()
			require.NotNil(t, sdk)

			ctx := context.Background()
			require.NoError(t, sdk.Health().Ping(ctx))

			data := []byte(`{"backend":"` + tc.name + `"}`)
			put, err := sdk.KV().Put(ctx, &quicbaassdk.PutRequest{
				EntityType: "factory-backend",
				Data:       data,
			})
			require.NoError(t, err)

			got, err := sdk.KV().Get(ctx, &quicbaassdk.GetRequest{
				EntityType: "factory-backend",
				ID:         put.ID,
			})
			require.NoError(t, err)
			assert.True(t, got.Found)
			assert.Equal(t, data, got.Data)
		})
	}
}

func TestFactory_UserDAO_Success(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	dao, err := factory.UserDAO()
	require.NoError(t, err)
	assert.NotNil(t, dao)

	// Second call should return same instance
	dao2, err := factory.UserDAO()
	require.NoError(t, err)
	assert.Same(t, dao, dao2)
}

func TestFactory_UserDAO_FactoryClosed(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	cleanup()

	_, err := factory.UserDAO()
	require.Error(t, err)

	var closedErr ErrFactoryClosed
	assert.ErrorAs(t, err, &closedErr)
}

func TestFactory_RegistrationDAO_Success(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	dao, err := factory.RegistrationDAO()
	require.NoError(t, err)
	assert.NotNil(t, dao)

	// Second call should return same instance
	dao2, err := factory.RegistrationDAO()
	require.NoError(t, err)
	assert.Same(t, dao, dao2)
}

func TestFactory_RegistrationDAO_FactoryClosed(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	cleanup()

	_, err := factory.RegistrationDAO()
	require.Error(t, err)

	var closedErr ErrFactoryClosed
	assert.ErrorAs(t, err, &closedErr)
}

func TestFactory_RoleDAO_Success(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	dao, err := factory.RoleDAO()
	require.NoError(t, err)
	assert.NotNil(t, dao)

	// Second call should return same instance
	dao2, err := factory.RoleDAO()
	require.NoError(t, err)
	assert.Same(t, dao, dao2)
}

func TestFactory_RoleDAO_FactoryClosed(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	cleanup()

	_, err := factory.RoleDAO()
	require.Error(t, err)

	var closedErr ErrFactoryClosed
	assert.ErrorAs(t, err, &closedErr)
}

func TestFactory_WebAuthnDAO_Success(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	dao, err := factory.WebAuthnDAO()
	require.NoError(t, err)
	assert.NotNil(t, dao)

	// Second call should return same instance
	dao2, err := factory.WebAuthnDAO()
	require.NoError(t, err)
	assert.Same(t, dao, dao2)
}

func TestFactory_WebAuthnDAO_FactoryClosed(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	cleanup()

	_, err := factory.WebAuthnDAO()
	require.Error(t, err)

	var closedErr ErrFactoryClosed
	assert.ErrorAs(t, err, &closedErr)
}

func TestFactory_SerializerType(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	assert.Equal(t, serializer.SERIALIZER_JSON, factory.SerializerType())
}

func TestFactory_Client(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	client := factory.Client()
	assert.NotNil(t, client)
	assert.True(t, client.IsStarted())
}

func TestFactory_ConcurrentDAOAccess(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	var wg sync.WaitGroup
	errors := make(chan error, 50)

	// Concurrently access all DAOs
	for i := 0; i < 10; i++ {
		wg.Add(4)

		go func() {
			defer wg.Done()
			_, err := factory.UserDAO()
			if err != nil {
				errors <- err
			}
		}()

		go func() {
			defer wg.Done()
			_, err := factory.RegistrationDAO()
			if err != nil {
				errors <- err
			}
		}()

		go func() {
			defer wg.Done()
			_, err := factory.RoleDAO()
			if err != nil {
				errors <- err
			}
		}()

		go func() {
			defer wg.Done()
			_, err := factory.WebAuthnDAO()
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("unexpected error in concurrent access: %v", err)
	}
}

func TestFactory_AllDAOs_Integration(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	// Get all DAOs
	userDAO, err := factory.UserDAO()
	require.NoError(t, err)

	roleDAO, err := factory.RoleDAO()
	require.NoError(t, err)

	regDAO, err := factory.RegistrationDAO()
	require.NoError(t, err)

	webAuthnDAO, err := factory.WebAuthnDAO()
	require.NoError(t, err)

	// Verify they all work
	assert.NotNil(t, userDAO)
	assert.NotNil(t, roleDAO)
	assert.NotNil(t, regDAO)
	assert.NotNil(t, webAuthnDAO)
}
