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
	TenantID string
	Email    string
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
	m.listUsersEmailCalls = append(m.listUsersEmailCalls, listUsersEmailCall{TenantID: tenantID, Email: email})
	m.mu.Unlock()

	if m.listUsersByEmailFunc != nil {
		return m.listUsersByEmailFunc(ctx, tenantID, email)
	}
	return []sdkiam.User{}, nil
}

// listUsersCalls returns the email call records, aliased for backward compatibility
// with tests that reference iamService.listUsersCalls[0].Email.
func (m *mockIAMServiceClient) getListUsersCalls() []listUsersEmailCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listUsersEmailCalls
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

	writeCalls      []mockWriteCall
	success200Calls []mockSuccessCall
	success201Calls []mockSuccessCall
	error200Calls   []mockErrorCall
	error401Calls   []mockErrorCall
	error400Calls   []mockErrorCall
	error403Calls   []mockForbiddenCall
	error404Calls   []mockErrorCall
	error500Calls   []mockErrorCall
}

type mockWriteCall struct {
	Status   int
	Response interface{}
}

type mockSuccessCall struct {
	Payload interface{}
}

type mockErrorCall struct {
	Err error
}

type mockForbiddenCall struct {
	Err     error
	Payload interface{}
}

func newMockHttpWriter() *mockHttpWriter {
	return &mockHttpWriter{}
}

func (m *mockHttpWriter) Write(w http.ResponseWriter, r *http.Request, status int, response interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeCalls = append(m.writeCalls, mockWriteCall{Status: status, Response: response})
	w.WriteHeader(status)
}

func (m *mockHttpWriter) WriteYaml(w http.ResponseWriter, status int, response interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeCalls = append(m.writeCalls, mockWriteCall{Status: status, Response: response})
	w.WriteHeader(status)
}

func (m *mockHttpWriter) WriteJson(w http.ResponseWriter, status int, response interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeCalls = append(m.writeCalls, mockWriteCall{Status: status, Response: response})
	w.WriteHeader(status)
}

func (m *mockHttpWriter) Success200(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.success200Calls = append(m.success200Calls, mockSuccessCall{Payload: payload})
	w.WriteHeader(http.StatusOK)
}

func (m *mockHttpWriter) Success201(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.success201Calls = append(m.success201Calls, mockSuccessCall{Payload: payload})
	w.WriteHeader(http.StatusCreated)
}

func (m *mockHttpWriter) Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.error404Calls = append(m.error404Calls, mockErrorCall{Err: err})
	w.WriteHeader(http.StatusNotFound)
}

func (m *mockHttpWriter) Error200(w http.ResponseWriter, r *http.Request, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.error200Calls = append(m.error200Calls, mockErrorCall{Err: err})
	w.WriteHeader(http.StatusOK)
}

func (m *mockHttpWriter) Error401(w http.ResponseWriter, r *http.Request, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.error401Calls = append(m.error401Calls, mockErrorCall{Err: err})
	w.WriteHeader(http.StatusUnauthorized)
}

func (m *mockHttpWriter) Error400(w http.ResponseWriter, r *http.Request, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.error400Calls = append(m.error400Calls, mockErrorCall{Err: err})
	w.WriteHeader(http.StatusBadRequest)
}

func (m *mockHttpWriter) Error404(w http.ResponseWriter, r *http.Request, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.error404Calls = append(m.error404Calls, mockErrorCall{Err: err})
	w.WriteHeader(http.StatusNotFound)
}

func (m *mockHttpWriter) Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.error403Calls = append(m.error403Calls, mockForbiddenCall{Err: err, Payload: payload})
	w.WriteHeader(http.StatusForbidden)
}

func (m *mockHttpWriter) Error500(w http.ResponseWriter, r *http.Request, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.error500Calls = append(m.error500Calls, mockErrorCall{Err: err})
	w.WriteHeader(http.StatusInternalServerError)
}

// Helper methods for mock assertions

func (m *mockHttpWriter) getError401Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.error401Calls)
}

func (m *mockHttpWriter) getError403Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.error403Calls)
}

func (m *mockHttpWriter) getError500Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.error500Calls)
}

func (m *mockHttpWriter) getSuccess200Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.success200Calls)
}
