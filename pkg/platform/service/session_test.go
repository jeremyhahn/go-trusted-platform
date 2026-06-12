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

package service

import (
	"log/slog"
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSession(t *testing.T) {
	session := NewSession()

	require.NotNil(t, session)
	assert.Equal(t, datastore.ConsistencyLevelLocal, session.ConsistencyLevel())
	assert.True(t, session.IsSystemSession())
}

func TestCreateSession(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	user := &entities.User{
		ID:    1,
		Email: "test@example.com",
	}
	serviceClaims := []uint64{10, 20}
	requestedServiceID := uint64(10)

	session := CreateSession(
		logger,
		requestedServiceID,
		serviceClaims,
		user,
	)

	require.NotNil(t, session)
	assert.Equal(t, logger, session.Logger())
	assert.Equal(t, user, session.User())
	assert.Equal(t, requestedServiceID, session.RequestedServiceID())
	assert.False(t, session.IsSystemSession())
}

func TestServiceSession_ConsistencyLevel(t *testing.T) {
	session := &ServiceSession{
		consistencyLevel: datastore.ConsistencyLevelQuorum,
	}

	assert.Equal(t, datastore.ConsistencyLevelQuorum, session.ConsistencyLevel())
}

func TestServiceSession_Logger(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	session := &ServiceSession{
		logger: logger,
	}

	assert.Equal(t, logger, session.Logger())
}

func TestServiceSession_RequestedServiceID(t *testing.T) {
	session := &ServiceSession{
		requestedServiceID: 456,
	}

	assert.Equal(t, uint64(456), session.RequestedServiceID())
}

func TestServiceSession_User(t *testing.T) {
	user := &entities.User{
		ID:    100,
		Email: "user@example.com",
	}
	session := &ServiceSession{
		user: user,
	}

	assert.Equal(t, user, session.User())
}

func TestServiceSession_Close(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	session := &ServiceSession{
		logger: logger,
	}

	// Should not panic
	assert.NotPanics(t, func() {
		session.Close()
	})
}

func TestServiceSession_CloseWithoutLogger(t *testing.T) {
	session := &ServiceSession{}

	// Should not panic even without logger
	assert.NotPanics(t, func() {
		session.Close()
	})
}

func TestServiceSession_String(t *testing.T) {
	session := &ServiceSession{
		requestedServiceID: 42,
	}

	result := session.String()
	assert.Contains(t, result, "42")
	assert.Contains(t, result, "serviceID")
}

func TestServiceSession_Error(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	session := &ServiceSession{
		logger:             logger,
		requestedServiceID: 99,
	}

	// Should not panic
	assert.NotPanics(t, func() {
		session.Error(assert.AnError)
	})
}

func TestServiceSession_IsSystemSession_True(t *testing.T) {
	session := &ServiceSession{
		logger: nil,
	}

	assert.True(t, session.IsSystemSession())
}

func TestServiceSession_IsSystemSession_False(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	session := &ServiceSession{
		logger: logger,
	}

	assert.False(t, session.IsSystemSession())
}

func TestServiceSession_SetLogger(t *testing.T) {
	logger1 := logging.NewLogger(slog.LevelWarn, os.Stderr)
	logger2 := logging.NewLogger(slog.LevelDebug, os.Stderr)

	session := &ServiceSession{
		logger: logger1,
	}

	session.SetLogger(logger2)
	assert.Equal(t, logger2, session.Logger())
}

func TestServiceSession_FullWorkflow(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)

	// Create a user with admin role
	user := &entities.User{
		ID:    1,
		Email: "admin@example.com",
		Roles: []*entities.Role{
			{
				ID:   1,
				Name: common.ROLE_ADMIN,
			},
		},
	}

	serviceClaims := []uint64{100, 200}

	session := CreateSession(
		logger,
		100, // requested service
		serviceClaims,
		user,
	)

	// Verify session state
	assert.Equal(t, uint64(100), session.RequestedServiceID())
	assert.Equal(t, user, session.User())
	assert.False(t, session.IsSystemSession())

	// Close session
	session.Close()
}

func TestServiceSession_NilUser(t *testing.T) {
	session := &ServiceSession{
		user: nil,
	}

	assert.Nil(t, session.User())
}
