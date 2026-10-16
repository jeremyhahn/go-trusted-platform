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

package iam

import (
	"context"
	"net/http"
	"sync"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

// mockIAMServiceClient is a mock implementation of IAMServiceClient for testing.
type mockIAMServiceClient struct {
	mu sync.Mutex

	// GetUser mock
	getUserFunc  func(ctx context.Context, tenantID, userID string) (*sdkiam.User, error)
	getUserCalls []getUserCall

	// ListUsersByEmail mock
	listUsersByEmailFunc func(ctx context.Context, tenantID, email string) ([]sdkiam.User, error)
	listUsersEmailCalls  []listUsersEmailCall
}

type getUserCall struct {
	TenantID string
	UserID   string
}

// listUsersEmailCall records a call to ListUsersByEmail.
// Email field is exposed so tests can inspect it directly (e.g. listUsersCalls[0].Email).
type listUsersEmailCall struct {
	Email string
}

func newMockIAMServiceClient() *mockIAMServiceClient {
	return &mockIAMServiceClient{}
}

func (m *mockIAMServiceClient) GetUser(ctx context.Context, tenantID, userID string) (*sdkiam.User, error) {
	m.mu.Lock()
	m.getUserCalls = append(m.getUserCalls, getUserCall{TenantID: tenantID, UserID: userID})
	m.mu.Unlock()

	if m.getUserFunc != nil {
		return m.getUserFunc(ctx, tenantID, userID)
	}
	return nil, ErrUserNotFound{Identifier: userID}
}

func (m *mockIAMServiceClient) ListUsersByEmail(ctx context.Context, tenantID, email string) ([]sdkiam.User, error) {
	m.mu.Lock()
	m.listUsersEmailCalls = append(m.listUsersEmailCalls, listUsersEmailCall{Email: email})
	m.mu.Unlock()

	if m.listUsersByEmailFunc != nil {
		return m.listUsersByEmailFunc(ctx, tenantID, email)
	}
	return []sdkiam.User{}, nil
}

// mockPEPServiceClient is a mock implementation of PEPServiceClient for testing.
type mockPEPServiceClient struct {
	mu sync.Mutex

	// Check mock
	checkFunc  func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error)
	checkCalls []*sdkiam.CheckRequest

	// CheckBatch mock
	checkBatchFunc  func(ctx context.Context, req *sdkiam.CheckBatchRequest) (*sdkiam.CheckBatchResponse, error)
	checkBatchCalls []*sdkiam.CheckBatchRequest
}

func newMockPEPServiceClient() *mockPEPServiceClient {
	return &mockPEPServiceClient{}
}

func (m *mockPEPServiceClient) Check(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
	m.mu.Lock()
	m.checkCalls = append(m.checkCalls, req)
	m.mu.Unlock()

	if m.checkFunc != nil {
		return m.checkFunc(ctx, req)
	}
	return &sdkiam.CheckResponse{Allowed: true}, nil
}

func (m *mockPEPServiceClient) CheckBatch(ctx context.Context, req *sdkiam.CheckBatchRequest) (*sdkiam.CheckBatchResponse, error) {
	m.mu.Lock()
	m.checkBatchCalls = append(m.checkBatchCalls, req)
	m.mu.Unlock()

	if m.checkBatchFunc != nil {
		return m.checkBatchFunc(ctx, req)
	}
	return &sdkiam.CheckBatchResponse{AllAllowed: true}, nil
}

// mockHttpWriter is a mock implementation of response.HttpWriter for testing.
type mockHttpWriter struct {
	mu sync.Mutex

	error401Calls int
	error403Calls int
	error500Calls int
}

func newMockHttpWriter() *mockHttpWriter {
	return &mockHttpWriter{}
}

func (m *mockHttpWriter) Write(w http.ResponseWriter, r *http.Request, status int, response interface{}) {
	w.WriteHeader(status)
}

func (m *mockHttpWriter) WriteYaml(w http.ResponseWriter, status int, response interface{}) {
	w.WriteHeader(status)
}

func (m *mockHttpWriter) WriteJson(w http.ResponseWriter, status int, response interface{}) {
	w.WriteHeader(status)
}

func (m *mockHttpWriter) Success200(w http.ResponseWriter, r *http.Request, payload interface{}) {
	w.WriteHeader(http.StatusOK)
}

func (m *mockHttpWriter) Success201(w http.ResponseWriter, r *http.Request, payload interface{}) {
	w.WriteHeader(http.StatusCreated)
}

func (m *mockHttpWriter) Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error) {
	w.WriteHeader(http.StatusNotFound)
}

func (m *mockHttpWriter) Error200(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusOK)
}

func (m *mockHttpWriter) Error401(w http.ResponseWriter, r *http.Request, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.error401Calls++
	w.WriteHeader(http.StatusUnauthorized)
}

func (m *mockHttpWriter) Error400(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusBadRequest)
}

func (m *mockHttpWriter) Error404(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusNotFound)
}

func (m *mockHttpWriter) Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.error403Calls++
	w.WriteHeader(http.StatusForbidden)
}

func (m *mockHttpWriter) Error500(w http.ResponseWriter, r *http.Request, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.error500Calls++
	w.WriteHeader(http.StatusInternalServerError)
}

func (m *mockHttpWriter) Error503(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusServiceUnavailable)
}

// Helper methods for mock assertions

func (m *mockHttpWriter) getError401Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.error401Calls
}

func (m *mockHttpWriter) getError403Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.error403Calls
}

func (m *mockHttpWriter) getError500Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.error500Calls
}
