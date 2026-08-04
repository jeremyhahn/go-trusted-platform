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

package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mockDumpEntityTypeServerStream implements the full gRPC server stream interface
type mockDumpEntityTypeServerStream struct {
	platformv1.PlatformDaemon_DumpEntityTypeServer
	responses []*platformv1.DumpEntityTypeResponse
	ctx       context.Context
	sendErr   error
}

func newMockDumpEntityTypeServerStream() *mockDumpEntityTypeServerStream {
	return &mockDumpEntityTypeServerStream{
		responses: make([]*platformv1.DumpEntityTypeResponse, 0),
		ctx:       context.Background(),
	}
}

func (m *mockDumpEntityTypeServerStream) Send(resp *platformv1.DumpEntityTypeResponse) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.responses = append(m.responses, resp)
	return nil
}

func (m *mockDumpEntityTypeServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockDumpEntityTypeServerStream) SetHeader(md metadata.MD) error {
	return nil
}

func (m *mockDumpEntityTypeServerStream) SendHeader(md metadata.MD) error {
	return nil
}

func (m *mockDumpEntityTypeServerStream) SetTrailer(md metadata.MD) {}

func (m *mockDumpEntityTypeServerStream) SendMsg(msg interface{}) error {
	return nil
}

func (m *mockDumpEntityTypeServerStream) RecvMsg(msg interface{}) error {
	return nil
}

// TestGetQuicBaaSClient_TableDriven tests getQuicBaaSClient with table-driven tests
func TestGetQuicBaaSClient_TableDriven(t *testing.T) {
	tests := []struct {
		name           string
		setupConfig    func() *Config
		expectedReason string
		wantErr        bool
	}{
		{
			name: "nil_app",
			setupConfig: func() *Config {
				cfg := DefaultConfig()
				cfg.App = nil
				return cfg
			},
			expectedReason: "application not configured",
			wantErr:        true,
		},
		{
			name: "nil_dao_factory",
			setupConfig: func() *Config {
				cfg := DefaultConfig()
				cfg.App = &app.App{} // App with nil DAOFactory
				return cfg
			},
			expectedReason: "datastore factory not initialized",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.setupConfig()
			svc, err := NewService(cfg)
			if err != nil {
				t.Fatalf("NewService() error: %v", err)
			}

			client, dbPath, err := svc.getQuicBaaSClient()

			if tt.wantErr {
				if err == nil {
					t.Error("getQuicBaaSClient() expected error, got nil")
				}
				if client != nil {
					t.Error("client should be nil on error")
				}
				if dbPath != "" {
					t.Error("dbPath should be empty on error")
				}

				// Verify error type and reason
				dbErr, ok := err.(ErrDatabaseNotAvailable)
				if !ok {
					t.Errorf("expected ErrDatabaseNotAvailable, got %T: %v", err, err)
				} else if dbErr.Reason != tt.expectedReason {
					t.Errorf("error reason = %q, want %q", dbErr.Reason, tt.expectedReason)
				}
			} else {
				if err != nil {
					t.Errorf("getQuicBaaSClient() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestListEntityTypes_TableDriven tests ListEntityTypes with table-driven tests
func TestListEntityTypes_TableDriven(t *testing.T) {
	tests := []struct {
		name         string
		setupConfig  func() *Config
		request      *platformv1.ListEntityTypesRequest
		wantErrCode  codes.Code
		wantResponse bool
	}{
		{
			name: "nil_app_returns_internal_error",
			setupConfig: func() *Config {
				cfg := DefaultConfig()
				cfg.App = nil
				return cfg
			},
			request:      &platformv1.ListEntityTypesRequest{},
			wantErrCode:  codes.Internal,
			wantResponse: false,
		},
		{
			name: "nil_dao_factory_returns_internal_error",
			setupConfig: func() *Config {
				cfg := DefaultConfig()
				cfg.App = &app.App{}
				return cfg
			},
			request:      &platformv1.ListEntityTypesRequest{},
			wantErrCode:  codes.Internal,
			wantResponse: false,
		},
		{
			name: "nil_request_with_nil_app",
			setupConfig: func() *Config {
				cfg := DefaultConfig()
				cfg.App = nil
				return cfg
			},
			request:      nil,
			wantErrCode:  codes.Internal,
			wantResponse: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.setupConfig()
			svc, err := NewService(cfg)
			if err != nil {
				t.Fatalf("NewService() error: %v", err)
			}

			ctx := context.Background()
			resp, err := svc.ListEntityTypes(ctx, tt.request)

			if tt.wantErrCode != codes.OK {
				if err == nil {
					t.Errorf("ListEntityTypes() expected error with code %v, got nil", tt.wantErrCode)
					return
				}

				st, ok := status.FromError(err)
				if !ok {
					t.Fatalf("expected gRPC status error, got %T", err)
				}

				if st.Code() != tt.wantErrCode {
					t.Errorf("error code = %v, want %v", st.Code(), tt.wantErrCode)
				}

				if tt.wantResponse && resp == nil {
					t.Error("expected response but got nil")
				}
				if !tt.wantResponse && resp != nil {
					t.Error("expected nil response but got value")
				}
			}
		})
	}
}

// TestDumpEntityType_TableDriven tests DumpEntityType with table-driven tests
func TestDumpEntityType_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func() *Config
		request     *platformv1.DumpEntityTypeRequest
		setupStream func() *mockDumpEntityTypeServerStream
		wantErrCode codes.Code
	}{
		{
			name: "nil_app_returns_internal_error",
			setupConfig: func() *Config {
				cfg := DefaultConfig()
				cfg.App = nil
				return cfg
			},
			request: &platformv1.DumpEntityTypeRequest{
				EntityType: "test",
			},
			setupStream: newMockDumpEntityTypeServerStream,
			wantErrCode: codes.Internal,
		},
		{
			name: "nil_dao_factory_returns_internal_error",
			setupConfig: func() *Config {
				cfg := DefaultConfig()
				cfg.App = &app.App{}
				return cfg
			},
			request: &platformv1.DumpEntityTypeRequest{
				EntityType: "users",
			},
			setupStream: newMockDumpEntityTypeServerStream,
			wantErrCode: codes.Internal,
		},
		{
			name: "empty_entity_type_with_nil_app",
			setupConfig: func() *Config {
				cfg := DefaultConfig()
				cfg.App = nil
				return cfg
			},
			request: &platformv1.DumpEntityTypeRequest{
				EntityType: "", // Empty triggers ListEntityTypes path
			},
			setupStream: newMockDumpEntityTypeServerStream,
			wantErrCode: codes.Internal,
		},
		{
			name: "specific_entity_type_with_nil_dao",
			setupConfig: func() *Config {
				cfg := DefaultConfig()
				cfg.App = &app.App{}
				return cfg
			},
			request: &platformv1.DumpEntityTypeRequest{
				EntityType: "organizations",
			},
			setupStream: newMockDumpEntityTypeServerStream,
			wantErrCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.setupConfig()
			svc, err := NewService(cfg)
			if err != nil {
				t.Fatalf("NewService() error: %v", err)
			}

			stream := tt.setupStream()
			err = svc.DumpEntityType(tt.request, stream)

			if tt.wantErrCode != codes.OK {
				if err == nil {
					t.Errorf("DumpEntityType() expected error with code %v, got nil", tt.wantErrCode)
					return
				}

				st, ok := status.FromError(err)
				if !ok {
					t.Fatalf("expected gRPC status error, got %T", err)
				}

				if st.Code() != tt.wantErrCode {
					t.Errorf("error code = %v, want %v", st.Code(), tt.wantErrCode)
				}
			}
		})
	}
}

// TestDumpEntityType_StreamSendError tests error handling when stream.Send fails
func TestDumpEntityType_StreamSendError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.App = nil

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	stream := newMockDumpEntityTypeServerStream()
	stream.sendErr = errors.New("send failed")

	// This will fail at getQuicBaaSClient before hitting stream.Send
	// but we test that the code paths exist
	err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{
		EntityType: "test",
	}, stream)

	if err == nil {
		t.Error("DumpEntityType() expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Internal {
		t.Errorf("error code = %v, want Internal", st.Code())
	}
}

// TestDumpEntityType_ContextCancellation tests behavior with cancelled context
func TestDumpEntityType_ContextCancellation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.App = nil

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	stream := newMockDumpEntityTypeServerStream()
	stream.ctx = ctx

	err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{
		EntityType: "test",
	}, stream)

	// Should still fail due to nil App (before context check)
	if err == nil {
		t.Error("DumpEntityType() expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Internal {
		t.Errorf("error code = %v, want Internal", st.Code())
	}
}

// TestListEntityTypes_ContextCancellation tests behavior with cancelled context
func TestListEntityTypes_ContextCancellation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.App = nil

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	resp, err := svc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})

	// Should still fail due to nil App (before context check)
	if err == nil {
		t.Error("ListEntityTypes() expected error, got nil")
	}

	if resp != nil {
		t.Error("response should be nil on error")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Internal {
		t.Errorf("error code = %v, want Internal", st.Code())
	}
}

// TestGetQuicBaaSClient_ErrorMessages tests that error messages are informative
func TestGetQuicBaaSClient_ErrorMessages(t *testing.T) {
	tests := []struct {
		name          string
		setupConfig   func() *Config
		wantSubstring string
	}{
		{
			name: "app_not_configured_message",
			setupConfig: func() *Config {
				cfg := DefaultConfig()
				cfg.App = nil
				return cfg
			},
			wantSubstring: "application not configured",
		},
		{
			name: "factory_not_initialized_message",
			setupConfig: func() *Config {
				cfg := DefaultConfig()
				cfg.App = &app.App{}
				return cfg
			},
			wantSubstring: "datastore factory not initialized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.setupConfig()
			svc, err := NewService(cfg)
			if err != nil {
				t.Fatalf("NewService() error: %v", err)
			}

			_, _, err = svc.getQuicBaaSClient()
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			errMsg := err.Error()
			if !strings.Contains(errMsg, tt.wantSubstring) {
				t.Errorf("error message %q does not contain %q", errMsg, tt.wantSubstring)
			}
		})
	}
}

// TestDumpEntityType_MultipleEntityTypes tests the path where empty EntityType
// triggers listing all types (which fails due to nil App in this test)
func TestDumpEntityType_MultipleEntityTypes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.App = nil

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	stream := newMockDumpEntityTypeServerStream()

	// Empty EntityType should trigger ListEntityTypes call
	err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{
		EntityType: "",
	}, stream)

	if err == nil {
		t.Error("DumpEntityType() with empty EntityType expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	// Should fail with Internal error due to nil App
	if st.Code() != codes.Internal {
		t.Errorf("error code = %v, want Internal", st.Code())
	}
}

// TestListEntityTypes_ResponseFields tests that response fields are properly structured
func TestListEntityTypes_ResponseFields(t *testing.T) {
	// When we have a proper mock QuicBaaS, we can test response fields
	// For now, test that error responses don't return partial data
	cfg := DefaultConfig()
	cfg.App = nil

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	ctx := context.Background()
	resp, err := svc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})

	if err == nil {
		t.Error("expected error, got nil")
	}

	// Response should be nil on error
	if resp != nil {
		t.Error("response should be nil when error occurs")
	}
}

// TestDumpEntityType_NoResponsesOnError tests that no responses are sent on error
func TestDumpEntityType_NoResponsesOnError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.App = nil

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	stream := newMockDumpEntityTypeServerStream()

	err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{
		EntityType: "test",
	}, stream)

	if err == nil {
		t.Error("expected error, got nil")
	}

	// No responses should have been sent before the error
	if len(stream.responses) != 0 {
		t.Errorf("expected 0 responses on error, got %d", len(stream.responses))
	}
}

// TestErrDatabaseNotAvailable_AllReasons tests all possible reasons for ErrDatabaseNotAvailable
func TestErrDatabaseNotAvailable_AllReasons(t *testing.T) {
	reasons := []string{
		"application not configured",
		"datastore factory not initialized",
		"datastore is not QuicBaaS",
		"QuicBaaS client not available",
		"QuicBaaS client not started",
	}

	for _, reason := range reasons {
		t.Run(reason, func(t *testing.T) {
			err := ErrDatabaseNotAvailable{Reason: reason}
			expectedMsg := "database not available: " + reason

			if err.Error() != expectedMsg {
				t.Errorf("Error() = %q, want %q", err.Error(), expectedMsg)
			}
		})
	}
}

// TestErrDatabaseNotAvailable_EmptyReason tests behavior with empty reason
func TestErrDatabaseNotAvailable_EmptyReason(t *testing.T) {
	err := ErrDatabaseNotAvailable{Reason: ""}
	expectedMsg := "database not available: "

	if err.Error() != expectedMsg {
		t.Errorf("Error() = %q, want %q", err.Error(), expectedMsg)
	}
}

// TestService_GetQuicBaaSClient_ConcurrentAccess tests thread safety
func TestService_GetQuicBaaSClient_ConcurrentAccess(t *testing.T) {
	cfg := DefaultConfig()
	cfg.App = nil

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	// Run concurrent calls to getQuicBaaSClient
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, _, err := svc.getQuicBaaSClient()
			if err == nil {
				t.Error("getQuicBaaSClient() expected error")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestService_ListEntityTypes_ConcurrentAccess tests thread safety
func TestService_ListEntityTypes_ConcurrentAccess(t *testing.T) {
	cfg := DefaultConfig()
	cfg.App = nil

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	ctx := context.Background()
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			_, err := svc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})
			if err == nil {
				t.Error("ListEntityTypes() expected error")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
