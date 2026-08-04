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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestGetQuicBaaSClient_AppNotConfigured tests the error path when App is nil
func TestGetQuicBaaSClient_AppNotConfigured(t *testing.T) {
	config := DefaultConfig()
	config.App = nil

	svc, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	client, dbPath, err := svc.getQuicBaaSClient()

	if err == nil {
		t.Error("getQuicBaaSClient() should return error when App is nil")
	}

	if client != nil {
		t.Error("client should be nil when App is nil")
	}

	if dbPath != "" {
		t.Error("dbPath should be empty when App is nil")
	}

	// Verify error type
	var dbErr ErrDatabaseNotAvailable
	if _, ok := err.(ErrDatabaseNotAvailable); !ok {
		t.Errorf("expected ErrDatabaseNotAvailable, got %T: %v", err, err)
	} else {
		dbErr = err.(ErrDatabaseNotAvailable)
		if dbErr.Reason != "application not configured" {
			t.Errorf("unexpected error reason: %s", dbErr.Reason)
		}
	}
}

// TestGetQuicBaaSClient_DAOFactoryNil tests error when DAOFactory returns nil
func TestGetQuicBaaSClient_DAOFactoryNil(t *testing.T) {
	// Create a minimal app with nil DAOFactory
	testApp := &app.App{}

	config := DefaultConfig()
	config.App = testApp

	svc, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	client, dbPath, err := svc.getQuicBaaSClient()

	if err == nil {
		t.Error("getQuicBaaSClient() should return error when DAOFactory is nil")
	}

	if client != nil {
		t.Error("client should be nil when DAOFactory is nil")
	}

	if dbPath != "" {
		t.Error("dbPath should be empty when DAOFactory is nil")
	}

	// Verify error type
	if _, ok := err.(ErrDatabaseNotAvailable); !ok {
		t.Errorf("expected ErrDatabaseNotAvailable, got %T: %v", err, err)
	} else {
		dbErr := err.(ErrDatabaseNotAvailable)
		if dbErr.Reason != "datastore factory not initialized" {
			t.Errorf("unexpected error reason: %s", dbErr.Reason)
		}
	}
}

// TestListEntityTypes_AppNotConfigured tests ListEntityTypes when App is nil
func TestListEntityTypes_AppNotConfigured(t *testing.T) {
	config := DefaultConfig()
	config.App = nil

	svc, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	ctx := context.Background()
	resp, err := svc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})

	if err == nil {
		t.Error("ListEntityTypes() should return error when App is nil")
	}

	if resp != nil {
		t.Error("response should be nil when error occurs")
	}

	// Verify gRPC status code
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Internal {
		t.Errorf("error code = %v, want Internal", st.Code())
	}

	// Verify error message contains expected text
	if st.Message() == "" {
		t.Error("error message should not be empty")
	}
}

// TestListEntityTypes_DAOFactoryNil tests ListEntityTypes when DAOFactory is nil
func TestListEntityTypes_DAOFactoryNil(t *testing.T) {
	testApp := &app.App{}

	config := DefaultConfig()
	config.App = testApp

	svc, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	ctx := context.Background()
	resp, err := svc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})

	if err == nil {
		t.Error("ListEntityTypes() should return error when DAOFactory is nil")
	}

	if resp != nil {
		t.Error("response should be nil when error occurs")
	}

	// Verify gRPC status code
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Internal {
		t.Errorf("error code = %v, want Internal", st.Code())
	}
}

// TestDumpEntityType_AppNotConfigured tests DumpEntityType when App is nil
func TestDumpEntityType_AppNotConfigured(t *testing.T) {
	config := DefaultConfig()
	config.App = nil

	svc, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	// Create a mock stream (uses existing mock from service_extended_test.go)
	mockStream := &mockDumpEntityTypeStream{}

	err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{
		EntityType: "test",
	}, mockStream)

	if err == nil {
		t.Error("DumpEntityType() should return error when App is nil")
	}

	// Verify gRPC status code
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Internal {
		t.Errorf("error code = %v, want Internal", st.Code())
	}
}

// TestDumpEntityType_DAOFactoryNil tests DumpEntityType when DAOFactory is nil
func TestDumpEntityType_DAOFactoryNil(t *testing.T) {
	testApp := &app.App{}

	config := DefaultConfig()
	config.App = testApp

	svc, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	mockStream := &mockDumpEntityTypeStream{}

	err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{
		EntityType: "test",
	}, mockStream)

	if err == nil {
		t.Error("DumpEntityType() should return error when DAOFactory is nil")
	}

	// Verify gRPC status code
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Internal {
		t.Errorf("error code = %v, want Internal", st.Code())
	}
}

// TestDumpEntityType_EmptyEntityType tests DumpEntityType with empty entity type (dumps all)
func TestDumpEntityType_EmptyEntityType(t *testing.T) {
	config := DefaultConfig()
	config.App = nil

	svc, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	mockStream := &mockDumpEntityTypeStream{}

	// Request with empty EntityType should still fail due to no App
	err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{
		EntityType: "",
	}, mockStream)

	if err == nil {
		t.Error("DumpEntityType() should return error when App is nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Internal {
		t.Errorf("error code = %v, want Internal", st.Code())
	}
}

// TestErrDatabaseNotAvailable_ErrorMessage tests the ErrDatabaseNotAvailable error message
func TestErrDatabaseNotAvailable_ErrorMessage(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "application not configured",
			reason:   "application not configured",
			expected: "database not available: application not configured",
		},
		{
			name:     "datastore factory not initialized",
			reason:   "datastore factory not initialized",
			expected: "database not available: datastore factory not initialized",
		},
		{
			name:     "datastore is not QuicBaaS",
			reason:   "datastore is not QuicBaaS",
			expected: "database not available: datastore is not QuicBaaS",
		},
		{
			name:     "QuicBaaS client not available",
			reason:   "QuicBaaS client not available",
			expected: "database not available: QuicBaaS client not available",
		},
		{
			name:     "QuicBaaS client not started",
			reason:   "QuicBaaS client not started",
			expected: "database not available: QuicBaaS client not started",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrDatabaseNotAvailable{Reason: tt.reason}
			if err.Error() != tt.expected {
				t.Errorf("Error() = %q, want %q", err.Error(), tt.expected)
			}
		})
	}
}
