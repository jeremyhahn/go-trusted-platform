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
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockWebAuthnDAO implements datastore.WebAuthnDAO for testing
type MockWebAuthnDAO struct {
	mock.Mock
}

func (m *MockWebAuthnDAO) Save(ctx context.Context, blob *entities.Blob) error {
	args := m.Called(ctx, blob)
	return args.Error(0)
}

func (m *MockWebAuthnDAO) Get(ctx context.Context, id uint64) (*entities.Blob, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Blob), args.Error(1)
}

func (m *MockWebAuthnDAO) Delete(ctx context.Context, blob *entities.Blob) error {
	args := m.Called(ctx, blob)
	return args.Error(0)
}

func (m *MockWebAuthnDAO) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

func (m *MockWebAuthnDAO) Page(ctx context.Context, pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Blob], error) {
	args := m.Called(ctx, pageQuery)
	return args.Get(0).(datastore.PageResult[*entities.Blob]), args.Error(1)
}

func (m *MockWebAuthnDAO) ForEachPage(ctx context.Context, pageQuery datastore.PageQuery, fn datastore.PagerFunc[*entities.Blob]) error {
	args := m.Called(ctx, pageQuery, fn)
	return args.Error(0)
}

func TestNewWebAuthnSessionService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)

	service := NewWebAuthnSessionService(logger, mockDAO)

	require.NotNil(t, service)
	assert.IsType(t, &WebAuthnSessionService{}, service)
}

func TestWebAuthnSessionService_Save_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	sessionData := entities.NewBlob(1, []byte("webauthn-session-data"))

	mockDAO.On("Save", ctx, sessionData).Return(nil)

	service := NewWebAuthnSessionService(logger, mockDAO)
	err := service.Save(ctx, sessionData)

	require.NoError(t, err)
	mockDAO.AssertExpectations(t)
}

func TestWebAuthnSessionService_Save_Error(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	sessionData := entities.NewBlob(1, []byte("webauthn-session-data"))

	expectedErr := errors.New("database error")
	mockDAO.On("Save", ctx, sessionData).Return(expectedErr)

	service := NewWebAuthnSessionService(logger, mockDAO)
	err := service.Save(ctx, sessionData)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	mockDAO.AssertExpectations(t)
}

func TestWebAuthnSessionService_Get_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	sessionID := uint64(123)
	expectedSession := entities.NewBlob(sessionID, []byte("session-data"))

	mockDAO.On("Get", ctx, sessionID).Return(expectedSession, nil)

	service := NewWebAuthnSessionService(logger, mockDAO)
	session, err := service.Get(ctx, sessionID)

	require.NoError(t, err)
	require.NotNil(t, session)
	assert.Equal(t, sessionID, session.ID)
	assert.Equal(t, []byte("session-data"), session.Bytes)
	mockDAO.AssertExpectations(t)
}

func TestWebAuthnSessionService_Get_NotFound(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	sessionID := uint64(999)
	expectedErr := ErrWebAuthnNotFound

	mockDAO.On("Get", ctx, sessionID).Return(nil, expectedErr)

	service := NewWebAuthnSessionService(logger, mockDAO)
	session, err := service.Get(ctx, sessionID)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, session)
	mockDAO.AssertExpectations(t)
}

func TestWebAuthnSessionService_Get_Error(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	sessionID := uint64(456)
	expectedErr := errors.New("database connection error")

	mockDAO.On("Get", ctx, sessionID).Return(nil, expectedErr)

	service := NewWebAuthnSessionService(logger, mockDAO)
	session, err := service.Get(ctx, sessionID)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, session)
	mockDAO.AssertExpectations(t)
}

func TestWebAuthnSessionService_Delete_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	sessionData := entities.NewBlob(789, []byte("session-to-delete"))

	mockDAO.On("Delete", ctx, sessionData).Return(nil)

	service := NewWebAuthnSessionService(logger, mockDAO)
	err := service.Delete(ctx, sessionData)

	require.NoError(t, err)
	mockDAO.AssertExpectations(t)
}

func TestWebAuthnSessionService_Delete_Error(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	sessionData := entities.NewBlob(789, []byte("session-to-delete"))

	expectedErr := errors.New("deletion failed")
	mockDAO.On("Delete", ctx, sessionData).Return(expectedErr)

	service := NewWebAuthnSessionService(logger, mockDAO)
	err := service.Delete(ctx, sessionData)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	mockDAO.AssertExpectations(t)
}

func TestWebAuthnSessionService_Page_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	pageQuery := datastore.PageQuery{
		Page:     1,
		PageSize: 10,
	}

	blobs := []*entities.Blob{
		entities.NewBlob(1, []byte("session-1")),
		entities.NewBlob(2, []byte("session-2")),
		entities.NewBlob(3, []byte("session-3")),
	}

	expectedResult := datastore.PageResult[*entities.Blob]{
		Entities: blobs,
		Page:     1,
		PageSize: 10,
		HasMore:  false,
	}

	mockDAO.On("Page", ctx, pageQuery).Return(expectedResult, nil)

	service := NewWebAuthnSessionService(logger, mockDAO)
	result, err := service.Page(ctx, pageQuery)

	require.NoError(t, err)
	assert.Equal(t, 3, len(result.Entities))
	assert.Equal(t, uint64(1), result.Entities[0].ID)
	assert.Equal(t, uint64(2), result.Entities[1].ID)
	assert.Equal(t, uint64(3), result.Entities[2].ID)
	mockDAO.AssertExpectations(t)
}

func TestWebAuthnSessionService_Page_Error(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	pageQuery := datastore.PageQuery{
		Page:     1,
		PageSize: 10,
	}

	expectedErr := errors.New("database error")
	mockDAO.On("Page", ctx, pageQuery).
		Return(datastore.PageResult[*entities.Blob]{}, expectedErr)

	service := NewWebAuthnSessionService(logger, mockDAO)
	result, err := service.Page(ctx, pageQuery)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Equal(t, 0, len(result.Entities))
	mockDAO.AssertExpectations(t)
}

func TestWebAuthnSessionService_Page_EmptyResult(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	pageQuery := datastore.PageQuery{
		Page:     5,
		PageSize: 10,
	}

	expectedResult := datastore.PageResult[*entities.Blob]{
		Entities: []*entities.Blob{},
		Page:     5,
		PageSize: 10,
		HasMore:  false,
	}

	mockDAO.On("Page", ctx, pageQuery).Return(expectedResult, nil)

	service := NewWebAuthnSessionService(logger, mockDAO)
	result, err := service.Page(ctx, pageQuery)

	require.NoError(t, err)
	assert.Equal(t, 0, len(result.Entities))
	assert.Equal(t, 5, result.Page)
	mockDAO.AssertExpectations(t)
}

func TestWebAuthnSessionService_Page_WithHasMore(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	pageQuery := datastore.PageQuery{
		Page:     1,
		PageSize: 2,
	}

	blobs := []*entities.Blob{
		entities.NewBlob(1, []byte("session-1")),
		entities.NewBlob(2, []byte("session-2")),
	}

	expectedResult := datastore.PageResult[*entities.Blob]{
		Entities: blobs,
		Page:     1,
		PageSize: 2,
		HasMore:  true,
	}

	mockDAO.On("Page", ctx, pageQuery).Return(expectedResult, nil)

	service := NewWebAuthnSessionService(logger, mockDAO)
	result, err := service.Page(ctx, pageQuery)

	require.NoError(t, err)
	assert.Equal(t, 2, len(result.Entities))
	assert.True(t, result.HasMore)
	mockDAO.AssertExpectations(t)
}

func TestWebAuthnSessionService_FullWorkflow(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	service := NewWebAuthnSessionService(logger, mockDAO)

	// Create session
	sessionData := entities.NewBlob(100, []byte("workflow-session-data"))

	mockDAO.On("Save", ctx, sessionData).Return(nil)
	err := service.Save(ctx, sessionData)
	require.NoError(t, err)

	// Get session
	mockDAO.On("Get", ctx, sessionData.ID).Return(sessionData, nil).Once()
	fetched, err := service.Get(ctx, sessionData.ID)
	require.NoError(t, err)
	assert.Equal(t, sessionData.Bytes, fetched.Bytes)

	// Delete session
	mockDAO.On("Delete", ctx, sessionData).Return(nil)
	err = service.Delete(ctx, sessionData)
	require.NoError(t, err)

	// Verify deletion
	mockDAO.On("Get", ctx, sessionData.ID).Return(nil, ErrWebAuthnNotFound).Once()
	fetched, err = service.Get(ctx, sessionData.ID)
	assert.Error(t, err)
	assert.Nil(t, fetched)

	mockDAO.AssertExpectations(t)
}

func TestWebAuthnSessionService_SaveMultiple(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	service := NewWebAuthnSessionService(logger, mockDAO)

	sessions := []*entities.Blob{
		entities.NewBlob(1, []byte("session-1")),
		entities.NewBlob(2, []byte("session-2")),
		entities.NewBlob(3, []byte("session-3")),
	}

	for _, session := range sessions {
		mockDAO.On("Save", ctx, session).Return(nil).Once()
		err := service.Save(ctx, session)
		require.NoError(t, err)
	}

	mockDAO.AssertExpectations(t)
}

func TestErrWebAuthnNotFound(t *testing.T) {
	assert.Equal(t, "service/webauthn: webauthn session data not found", ErrWebAuthnNotFound.Error())
}

func TestWebAuthnSessionService_GetWithDifferentIDs(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	service := NewWebAuthnSessionService(logger, mockDAO)

	testCases := []struct {
		name      string
		sessionID uint64
		bytes     []byte
	}{
		{name: "small id", sessionID: 1, bytes: []byte("small-id-session")},
		{name: "medium id", sessionID: 1000, bytes: []byte("medium-id-session")},
		{name: "large id", sessionID: 999999, bytes: []byte("large-id-session")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session := entities.NewBlob(tc.sessionID, tc.bytes)
			mockDAO.On("Get", ctx, tc.sessionID).Return(session, nil).Once()

			result, err := service.Get(ctx, tc.sessionID)
			require.NoError(t, err)
			assert.Equal(t, tc.sessionID, result.ID)
			assert.Equal(t, tc.bytes, result.Bytes)
		})
	}

	mockDAO.AssertExpectations(t)
}

func TestWebAuthnSessionService_DeleteNilSession(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	var nilSession *entities.Blob

	mockDAO.On("Delete", ctx, nilSession).Return(nil)

	service := NewWebAuthnSessionService(logger, mockDAO)
	err := service.Delete(ctx, nilSession)

	require.NoError(t, err)
	mockDAO.AssertExpectations(t)
}

func TestWebAuthnSessionService_SaveWithEmptyData(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	sessionData := entities.NewBlob(123, []byte{})

	mockDAO.On("Save", ctx, sessionData).Return(nil)

	service := NewWebAuthnSessionService(logger, mockDAO)
	err := service.Save(ctx, sessionData)

	require.NoError(t, err)
	mockDAO.AssertExpectations(t)
}

func TestWebAuthnSessionService_SaveWithLargeData(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockWebAuthnDAO)
	ctx := context.Background()

	// Create large data blob (1MB)
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	sessionData := entities.NewBlob(456, largeData)

	mockDAO.On("Save", ctx, sessionData).Return(nil)

	service := NewWebAuthnSessionService(logger, mockDAO)
	err := service.Save(ctx, sessionData)

	require.NoError(t, err)
	mockDAO.AssertExpectations(t)
}
