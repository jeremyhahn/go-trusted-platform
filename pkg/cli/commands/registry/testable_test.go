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

package registry

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// MockPrinter implements Printer interface for testing
type MockPrinter struct {
	PrintFunc         func(v interface{}) error
	PrintKeyValueFunc func(key, value string)
	PrintSuccessFunc  func(message string)
	PrintInfoFunc     func(message string)
	PrintWarningFunc  func(message string)
	PrintErrorFunc    func(message string)
	Output            *bytes.Buffer
}

func (m *MockPrinter) Print(v interface{}) error {
	if m.PrintFunc != nil {
		return m.PrintFunc(v)
	}
	return nil
}

func (m *MockPrinter) PrintKeyValue(key, value string) {
	if m.PrintKeyValueFunc != nil {
		m.PrintKeyValueFunc(key, value)
	}
}

func (m *MockPrinter) PrintSuccess(message string) {
	if m.PrintSuccessFunc != nil {
		m.PrintSuccessFunc(message)
	}
}

func (m *MockPrinter) PrintInfo(message string) {
	if m.PrintInfoFunc != nil {
		m.PrintInfoFunc(message)
	}
}

func (m *MockPrinter) PrintWarning(message string) {
	if m.PrintWarningFunc != nil {
		m.PrintWarningFunc(message)
	}
}

func (m *MockPrinter) PrintError(message string) {
	if m.PrintErrorFunc != nil {
		m.PrintErrorFunc(message)
	}
}

func newMockPrinter() *MockPrinter {
	return &MockPrinter{
		Output: &bytes.Buffer{},
	}
}

// MockRegistryClient implements RegistryClient for testing
type MockRegistryClient struct {
	PushFunc    func(ctx context.Context, req *PushRequest) (*PushResult, error)
	PullFunc    func(ctx context.Context, req *PullRequest) (*PullResult, error)
	ListFunc    func(ctx context.Context, req *ListRequest) (*ListResult, error)
	DeleteFunc  func(ctx context.Context, req *DeleteRequest) (*DeleteResultCLI, error)
	InspectFunc func(ctx context.Context, req *InspectRequest) (*InspectResult, error)
	StatusFunc  func(ctx context.Context, req *StatusRequest) (*StatusResult, error)
}

func (m *MockRegistryClient) Push(ctx context.Context, req *PushRequest) (*PushResult, error) {
	if m.PushFunc != nil {
		return m.PushFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *MockRegistryClient) Pull(ctx context.Context, req *PullRequest) (*PullResult, error) {
	if m.PullFunc != nil {
		return m.PullFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *MockRegistryClient) List(ctx context.Context, req *ListRequest) (*ListResult, error) {
	if m.ListFunc != nil {
		return m.ListFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *MockRegistryClient) Delete(ctx context.Context, req *DeleteRequest) (*DeleteResultCLI, error) {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *MockRegistryClient) Inspect(ctx context.Context, req *InspectRequest) (*InspectResult, error) {
	if m.InspectFunc != nil {
		return m.InspectFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *MockRegistryClient) Status(ctx context.Context, req *StatusRequest) (*StatusResult, error) {
	if m.StatusFunc != nil {
		return m.StatusFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

// Push Tests

func TestExecutePush_Success(t *testing.T) {
	tests := []struct {
		name    string
		format  cli.OutputFormat
		req     *PushRequest
		resp    *PushResult
		wantErr bool
	}{
		{
			name:   "basic push - table format",
			format: cli.OutputFormatTable,
			req: &PushRequest{
				Reference: "myrepo/myimage:v1.0",
				Encrypt:   false,
			},
			resp: &PushResult{
				Reference: "myrepo/myimage:v1.0",
				Digest:    "sha256:abc123def456",
				Size:      1024000,
				Encrypted: false,
				Signed:    false,
				Timestamp: 1704067200,
			},
			wantErr: false,
		},
		{
			name:   "encrypted push - table format",
			format: cli.OutputFormatTable,
			req: &PushRequest{
				Reference: "myrepo/myimage:v2.0",
				Encrypt:   true,
				KeyID:     "my-encryption-key",
			},
			resp: &PushResult{
				Reference: "myrepo/myimage:v2.0",
				Digest:    "sha256:encrypted123",
				Size:      2048000,
				Encrypted: true,
				KeyID:     "my-encryption-key",
				Signed:    false,
				Timestamp: 1704153600,
			},
			wantErr: false,
		},
		{
			name:   "signed push - JSON format",
			format: cli.OutputFormatJSON,
			req: &PushRequest{
				Reference:    "myrepo/myimage:v3.0",
				Sign:         true,
				SigningKeyID: "my-signing-key",
			},
			resp: &PushResult{
				Reference: "myrepo/myimage:v3.0",
				Digest:    "sha256:signed789",
				Size:      512000,
				Encrypted: false,
				Signed:    true,
				Timestamp: 1704240000,
			},
			wantErr: false,
		},
		{
			name:   "push - YAML format",
			format: cli.OutputFormatYAML,
			req: &PushRequest{
				Reference: "myrepo/myimage:latest",
			},
			resp: &PushResult{
				Reference: "myrepo/myimage:latest",
				Digest:    "sha256:latest123",
				Size:      768000,
				Timestamp: 1704326400,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockRegistryClient{
				PushFunc: func(ctx context.Context, req *PushRequest) (*PushResult, error) {
					return tt.resp, nil
				},
			}

			printer := newMockPrinter()

			exec := &CommandExecutor{
				Client:       mockClient,
				Printer:      printer,
				Ctx:          context.Background(),
				OutputFormat: tt.format,
			}

			err := executePush(exec, tt.req)

			if (err != nil) != tt.wantErr {
				t.Errorf("executePush() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecutePush_InvalidImageReference(t *testing.T) {
	mockClient := &MockRegistryClient{}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	tests := []struct {
		name string
		ref  string
	}{
		{name: "empty reference", ref: ""},
		{name: "too long reference", ref: string(make([]byte, 300))},
		{name: "invalid characters", ref: "INVALID/UPPERCASE:tag"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &PushRequest{Reference: tt.ref}
			err := executePush(exec, req)

			if err == nil {
				t.Error("expected error for invalid reference")
			}
			if _, ok := err.(ErrInvalidImageReference); !ok {
				t.Errorf("expected ErrInvalidImageReference, got %T: %v", err, err)
			}
		})
	}
}

func TestExecutePush_EncryptionRequiresKeyID(t *testing.T) {
	mockClient := &MockRegistryClient{}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &PushRequest{
		Reference: "myrepo/myimage:v1.0",
		Encrypt:   true,
		KeyID:     "",
	}

	err := executePush(exec, req)

	if err == nil {
		t.Error("expected error when encrypt is true but keyID is empty")
	}
	if _, ok := err.(ErrEncryptionKeyRequired); !ok {
		t.Errorf("expected ErrEncryptionKeyRequired, got %T: %v", err, err)
	}
}

func TestExecutePush_ClientError(t *testing.T) {
	expectedErr := errors.New("connection refused")
	mockClient := &MockRegistryClient{
		PushFunc: func(ctx context.Context, req *PushRequest) (*PushResult, error) {
			return nil, expectedErr
		},
	}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &PushRequest{Reference: "myrepo/myimage:v1.0"}

	err := executePush(exec, req)

	if err == nil {
		t.Error("expected error for client failure")
	}
	if _, ok := err.(ErrPushFailed); !ok {
		t.Errorf("expected ErrPushFailed, got %T", err)
	}
}

func TestPrintPushResponse_InvalidFormat(t *testing.T) {
	printer := newMockPrinter()
	resp := &PushResult{
		Reference: "myrepo/myimage:v1.0",
	}

	err := printPushResponse(printer, "invalid", resp)

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestPrintPushResponse_PrinterError(t *testing.T) {
	expectedErr := errors.New("printer error")
	printer := &MockPrinter{
		PrintFunc: func(v interface{}) error {
			return expectedErr
		},
	}
	resp := &PushResult{
		Reference: "myrepo/myimage:v1.0",
	}

	err := printPushResponse(printer, cli.OutputFormatJSON, resp)

	if err == nil {
		t.Error("expected error from printer")
	}
	if err != expectedErr {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

// Pull Tests

func TestExecutePull_Success(t *testing.T) {
	tests := []struct {
		name    string
		format  cli.OutputFormat
		req     *PullRequest
		resp    *PullResult
		wantErr bool
	}{
		{
			name:   "basic pull - table format",
			format: cli.OutputFormatTable,
			req: &PullRequest{
				Reference: "myrepo/myimage:v1.0",
			},
			resp: &PullResult{
				Reference: "myrepo/myimage:v1.0",
				Digest:    "sha256:abc123def456",
				Size:      1024000,
				Decrypted: false,
				Verified:  false,
				Timestamp: 1704067200,
			},
			wantErr: false,
		},
		{
			name:   "decrypted pull - table format",
			format: cli.OutputFormatTable,
			req: &PullRequest{
				Reference: "myrepo/myimage:v2.0",
				Decrypt:   true,
			},
			resp: &PullResult{
				Reference: "myrepo/myimage:v2.0",
				Digest:    "sha256:decrypted123",
				Size:      2048000,
				Decrypted: true,
				Verified:  false,
				Timestamp: 1704153600,
			},
			wantErr: false,
		},
		{
			name:   "verified pull with platform - JSON format",
			format: cli.OutputFormatJSON,
			req: &PullRequest{
				Reference: "myrepo/myimage:v3.0",
				Verify:    true,
				Platform:  "linux/amd64",
			},
			resp: &PullResult{
				Reference: "myrepo/myimage:v3.0",
				Digest:    "sha256:verified789",
				Size:      512000,
				Decrypted: false,
				Verified:  true,
				Platform:  "linux/amd64",
				Timestamp: 1704240000,
			},
			wantErr: false,
		},
		{
			name:   "pull - YAML format",
			format: cli.OutputFormatYAML,
			req: &PullRequest{
				Reference: "myrepo/myimage:latest",
			},
			resp: &PullResult{
				Reference: "myrepo/myimage:latest",
				Digest:    "sha256:latest123",
				Size:      768000,
				Timestamp: 1704326400,
			},
			wantErr: false,
		},
		{
			name:   "pull with platform - table format",
			format: cli.OutputFormatTable,
			req: &PullRequest{
				Reference: "myrepo/myimage:v5.0",
				Platform:  "linux/arm64",
			},
			resp: &PullResult{
				Reference: "myrepo/myimage:v5.0",
				Digest:    "sha256:platform123",
				Size:      512000,
				Platform:  "linux/arm64",
				Timestamp: 1704412800,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockRegistryClient{
				PullFunc: func(ctx context.Context, req *PullRequest) (*PullResult, error) {
					return tt.resp, nil
				},
			}

			printer := newMockPrinter()

			exec := &CommandExecutor{
				Client:       mockClient,
				Printer:      printer,
				Ctx:          context.Background(),
				OutputFormat: tt.format,
			}

			err := executePull(exec, tt.req)

			if (err != nil) != tt.wantErr {
				t.Errorf("executePull() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecutePull_InvalidImageReference(t *testing.T) {
	mockClient := &MockRegistryClient{}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &PullRequest{Reference: ""}
	err := executePull(exec, req)

	if err == nil {
		t.Error("expected error for empty reference")
	}
	if _, ok := err.(ErrInvalidImageReference); !ok {
		t.Errorf("expected ErrInvalidImageReference, got %T: %v", err, err)
	}
}

func TestExecutePull_ClientError(t *testing.T) {
	expectedErr := errors.New("image not found")
	mockClient := &MockRegistryClient{
		PullFunc: func(ctx context.Context, req *PullRequest) (*PullResult, error) {
			return nil, expectedErr
		},
	}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &PullRequest{Reference: "myrepo/myimage:v1.0"}

	err := executePull(exec, req)

	if err == nil {
		t.Error("expected error for client failure")
	}
	if _, ok := err.(ErrPullFailed); !ok {
		t.Errorf("expected ErrPullFailed, got %T", err)
	}
}

func TestPrintPullResponse_InvalidFormat(t *testing.T) {
	printer := newMockPrinter()
	resp := &PullResult{
		Reference: "myrepo/myimage:v1.0",
	}

	err := printPullResponse(printer, "invalid", resp)

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestPrintPullResponse_PrinterError(t *testing.T) {
	expectedErr := errors.New("printer error")
	printer := &MockPrinter{
		PrintFunc: func(v interface{}) error {
			return expectedErr
		},
	}
	resp := &PullResult{
		Reference: "myrepo/myimage:v1.0",
	}

	err := printPullResponse(printer, cli.OutputFormatJSON, resp)

	if err == nil {
		t.Error("expected error from printer")
	}
	if err != expectedErr {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

// List Tests

func TestExecuteList_Success(t *testing.T) {
	tests := []struct {
		name    string
		format  cli.OutputFormat
		req     *ListRequest
		resp    *ListResult
		wantErr bool
	}{
		{
			name:   "list with images - table format",
			format: cli.OutputFormatTable,
			req: &ListRequest{
				Limit: 50,
			},
			resp: &ListResult{
				Images: []*ImageListItem{
					{
						Reference: "myrepo/image1:v1.0",
						Digest:    "sha256:abc123",
						Size:      1024000,
						Encrypted: false,
						Signed:    true,
						PushedAt:  1704067200,
					},
					{
						Reference: "myrepo/image2:latest",
						Digest:    "sha256:def456",
						Size:      2048000,
						Encrypted: true,
						Signed:    false,
						PushedAt:  1704153600,
					},
				},
				TotalCount: 2,
				HasMore:    false,
			},
			wantErr: false,
		},
		{
			name:   "list with pagination - table format",
			format: cli.OutputFormatTable,
			req: &ListRequest{
				Limit: 10,
			},
			resp: &ListResult{
				Images: []*ImageListItem{
					{
						Reference: "myrepo/image1:v1.0",
						Digest:    "sha256:abc123",
						Size:      1024000,
						PushedAt:  1704067200,
					},
				},
				TotalCount: 100,
				HasMore:    true,
				NextCursor: "cursor-xyz123",
			},
			wantErr: false,
		},
		{
			name:   "empty list - table format",
			format: cli.OutputFormatTable,
			req: &ListRequest{
				Repository: "empty-repo",
			},
			resp: &ListResult{
				Images:     []*ImageListItem{},
				TotalCount: 0,
				HasMore:    false,
			},
			wantErr: false,
		},
		{
			name:   "list - JSON format",
			format: cli.OutputFormatJSON,
			req: &ListRequest{
				Limit: 50,
			},
			resp: &ListResult{
				Images: []*ImageListItem{
					{
						Reference: "myrepo/image1:v1.0",
					},
				},
				TotalCount: 1,
			},
			wantErr: false,
		},
		{
			name:   "list - YAML format",
			format: cli.OutputFormatYAML,
			req: &ListRequest{
				Limit: 50,
			},
			resp: &ListResult{
				Images: []*ImageListItem{
					{
						Reference: "myrepo/image1:v1.0",
					},
				},
				TotalCount: 1,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockRegistryClient{
				ListFunc: func(ctx context.Context, req *ListRequest) (*ListResult, error) {
					return tt.resp, nil
				},
			}

			printer := newMockPrinter()

			exec := &CommandExecutor{
				Client:       mockClient,
				Printer:      printer,
				Ctx:          context.Background(),
				OutputFormat: tt.format,
			}

			err := executeList(exec, tt.req)

			if (err != nil) != tt.wantErr {
				t.Errorf("executeList() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecuteList_ClientError(t *testing.T) {
	expectedErr := errors.New("database error")
	mockClient := &MockRegistryClient{
		ListFunc: func(ctx context.Context, req *ListRequest) (*ListResult, error) {
			return nil, expectedErr
		},
	}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &ListRequest{Limit: 50}

	err := executeList(exec, req)

	if err == nil {
		t.Error("expected error for client failure")
	}
	if _, ok := err.(ErrListFailed); !ok {
		t.Errorf("expected ErrListFailed, got %T", err)
	}
}

func TestPrintListResponse_InvalidFormat(t *testing.T) {
	printer := newMockPrinter()
	resp := &ListResult{
		Images: []*ImageListItem{
			{Reference: "myrepo/image:v1.0"},
		},
	}

	err := printListResponse(printer, "invalid", resp)

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestPrintListResponse_PrinterError(t *testing.T) {
	expectedErr := errors.New("printer error")
	printer := &MockPrinter{
		PrintFunc: func(v interface{}) error {
			return expectedErr
		},
	}
	resp := &ListResult{
		Images: []*ImageListItem{
			{Reference: "myrepo/image:v1.0"},
		},
	}

	err := printListResponse(printer, cli.OutputFormatJSON, resp)

	if err == nil {
		t.Error("expected error from printer")
	}
	if err != expectedErr {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

func TestPrintListResponse_TablePrintError(t *testing.T) {
	expectedErr := errors.New("table print error")
	printer := &MockPrinter{
		PrintFunc: func(v interface{}) error {
			return expectedErr
		},
	}
	resp := &ListResult{
		Images: []*ImageListItem{
			{Reference: "myrepo/image:v1.0"},
		},
		TotalCount: 1,
	}

	err := printListResponse(printer, cli.OutputFormatTable, resp)

	if err == nil {
		t.Error("expected error from table print")
	}
	if err != expectedErr {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

// Delete Tests

func TestExecuteDelete_Success(t *testing.T) {
	tests := []struct {
		name    string
		format  cli.OutputFormat
		req     *DeleteRequest
		resp    *DeleteResultCLI
		wantErr bool
	}{
		{
			name:   "successful deletion - table format",
			format: cli.OutputFormatTable,
			req: &DeleteRequest{
				Reference: "myrepo/myimage:v1.0",
				Force:     true,
			},
			resp: &DeleteResultCLI{
				Reference: "myrepo/myimage:v1.0",
				Digest:    "sha256:abc123",
				Deleted:   true,
				Timestamp: 1704067200,
			},
			wantErr: false,
		},
		{
			name:   "failed deletion - table format",
			format: cli.OutputFormatTable,
			req: &DeleteRequest{
				Reference: "myrepo/protected:v1.0",
				Force:     false,
			},
			resp: &DeleteResultCLI{
				Reference: "myrepo/protected:v1.0",
				Digest:    "sha256:protected123",
				Deleted:   false,
				Message:   "image is protected",
				Timestamp: 0,
			},
			wantErr: false,
		},
		{
			name:   "deletion - JSON format",
			format: cli.OutputFormatJSON,
			req: &DeleteRequest{
				Reference: "myrepo/myimage:v2.0",
			},
			resp: &DeleteResultCLI{
				Reference: "myrepo/myimage:v2.0",
				Digest:    "sha256:def456",
				Deleted:   true,
				Timestamp: 1704153600,
			},
			wantErr: false,
		},
		{
			name:   "deletion - YAML format",
			format: cli.OutputFormatYAML,
			req: &DeleteRequest{
				Reference: "myrepo/myimage:v3.0",
			},
			resp: &DeleteResultCLI{
				Reference: "myrepo/myimage:v3.0",
				Digest:    "sha256:ghi789",
				Deleted:   true,
				Timestamp: 1704240000,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockRegistryClient{
				DeleteFunc: func(ctx context.Context, req *DeleteRequest) (*DeleteResultCLI, error) {
					return tt.resp, nil
				},
			}

			printer := newMockPrinter()

			exec := &CommandExecutor{
				Client:       mockClient,
				Printer:      printer,
				Ctx:          context.Background(),
				OutputFormat: tt.format,
			}

			err := executeDelete(exec, tt.req)

			if (err != nil) != tt.wantErr {
				t.Errorf("executeDelete() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecuteDelete_DryRun(t *testing.T) {
	mockClient := &MockRegistryClient{}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &DeleteRequest{
		Reference: "myrepo/myimage:v1.0",
		DryRun:    true,
	}

	err := executeDelete(exec, req)

	if err != nil {
		t.Errorf("unexpected error for dry run: %v", err)
	}
}

func TestExecuteDelete_DryRun_JSONFormat(t *testing.T) {
	mockClient := &MockRegistryClient{}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatJSON,
	}

	req := &DeleteRequest{
		Reference: "myrepo/myimage:v1.0",
		DryRun:    true,
	}

	err := executeDelete(exec, req)

	if err != nil {
		t.Errorf("unexpected error for dry run with JSON format: %v", err)
	}
}

func TestExecuteDelete_DryRun_YAMLFormat(t *testing.T) {
	mockClient := &MockRegistryClient{}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatYAML,
	}

	req := &DeleteRequest{
		Reference: "myrepo/myimage:v1.0",
		DryRun:    true,
	}

	err := executeDelete(exec, req)

	if err != nil {
		t.Errorf("unexpected error for dry run with YAML format: %v", err)
	}
}

func TestExecuteDelete_InvalidImageReference(t *testing.T) {
	mockClient := &MockRegistryClient{}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &DeleteRequest{Reference: ""}
	err := executeDelete(exec, req)

	if err == nil {
		t.Error("expected error for empty reference")
	}
	if _, ok := err.(ErrInvalidImageReference); !ok {
		t.Errorf("expected ErrInvalidImageReference, got %T: %v", err, err)
	}
}

func TestExecuteDelete_ClientError(t *testing.T) {
	expectedErr := errors.New("permission denied")
	mockClient := &MockRegistryClient{
		DeleteFunc: func(ctx context.Context, req *DeleteRequest) (*DeleteResultCLI, error) {
			return nil, expectedErr
		},
	}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &DeleteRequest{Reference: "myrepo/myimage:v1.0"}

	err := executeDelete(exec, req)

	if err == nil {
		t.Error("expected error for client failure")
	}
	if _, ok := err.(ErrDeleteFailed); !ok {
		t.Errorf("expected ErrDeleteFailed, got %T", err)
	}
}

func TestPrintDeleteResponseTestable_InvalidFormat(t *testing.T) {
	printer := newMockPrinter()
	resp := &DeleteResultCLI{
		Reference: "myrepo/myimage:v1.0",
	}

	err := printDeleteResponseTestable(printer, "invalid", resp, false)

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestPrintDeleteResponseTestable_PrinterError(t *testing.T) {
	expectedErr := errors.New("printer error")
	printer := &MockPrinter{
		PrintFunc: func(v interface{}) error {
			return expectedErr
		},
	}
	resp := &DeleteResultCLI{
		Reference: "myrepo/myimage:v1.0",
	}

	err := printDeleteResponseTestable(printer, cli.OutputFormatJSON, resp, false)

	if err == nil {
		t.Error("expected error from printer")
	}
	if err != expectedErr {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

// Inspect Tests

func TestExecuteInspect_Success(t *testing.T) {
	tests := []struct {
		name    string
		format  cli.OutputFormat
		req     *InspectRequest
		resp    *InspectResult
		wantErr bool
	}{
		{
			name:   "basic inspect - table format",
			format: cli.OutputFormatTable,
			req: &InspectRequest{
				Reference: "myrepo/myimage:v1.0",
			},
			resp: &InspectResult{
				Manifest: &ImageManifest{
					Reference: "myrepo/myimage:v1.0",
					Digest:    "sha256:abc123def456",
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					SchemaVer: 2,
					Config: &ManifestConfig{
						Digest:    "sha256:config123",
						Size:      1024,
						MediaType: "application/vnd.oci.image.config.v1+json",
					},
					CreatedAt: 1704067200,
					PushedAt:  1704153600,
				},
			},
			wantErr: false,
		},
		{
			name:   "inspect with layers - table format",
			format: cli.OutputFormatTable,
			req: &InspectRequest{
				Reference:  "myrepo/myimage:v2.0",
				ShowLayers: true,
			},
			resp: &InspectResult{
				Manifest: &ImageManifest{
					Reference: "myrepo/myimage:v2.0",
					Digest:    "sha256:layered123",
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					SchemaVer: 2,
					Layers: []*LayerInfo{
						{
							Digest:    "sha256:layer1",
							Size:      512000,
							MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
							Encrypted: false,
						},
						{
							Digest:    "sha256:layer2",
							Size:      256000,
							MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
							Encrypted: true,
						},
					},
					CreatedAt: 1704067200,
					PushedAt:  1704153600,
				},
			},
			wantErr: false,
		},
		{
			name:   "inspect with signature - table format",
			format: cli.OutputFormatTable,
			req: &InspectRequest{
				Reference:     "myrepo/myimage:signed",
				ShowSignature: true,
			},
			resp: &InspectResult{
				Manifest: &ImageManifest{
					Reference: "myrepo/myimage:signed",
					Digest:    "sha256:signed123",
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					SchemaVer: 2,
					Signature: &SignatureInfo{
						Signed:      true,
						SignedBy:    "admin@example.com",
						KeyID:       "signing-key-123",
						Algorithm:   "ECDSA-P256",
						ValidatedAt: 1704240000,
						Valid:       true,
					},
					CreatedAt: 1704067200,
					PushedAt:  1704153600,
				},
			},
			wantErr: false,
		},
		{
			name:   "inspect with encryption - table format",
			format: cli.OutputFormatTable,
			req: &InspectRequest{
				Reference:      "myrepo/myimage:encrypted",
				ShowEncryption: true,
			},
			resp: &InspectResult{
				Manifest: &ImageManifest{
					Reference: "myrepo/myimage:encrypted",
					Digest:    "sha256:encrypted123",
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					SchemaVer: 2,
					Encryption: &EncryptionInfo{
						Encrypted:  true,
						KeyIDs:     []string{"key-1", "key-2"},
						Algorithm:  "AES-256-GCM",
						LayerCount: 3,
					},
					CreatedAt: 1704067200,
					PushedAt:  1704153600,
				},
			},
			wantErr: false,
		},
		{
			name:   "inspect with annotations - table format",
			format: cli.OutputFormatTable,
			req: &InspectRequest{
				Reference: "myrepo/myimage:annotated",
			},
			resp: &InspectResult{
				Manifest: &ImageManifest{
					Reference: "myrepo/myimage:annotated",
					Digest:    "sha256:annotated123",
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					SchemaVer: 2,
					Annotations: map[string]string{
						"org.opencontainers.image.title":   "My Image",
						"org.opencontainers.image.authors": "admin@example.com",
					},
					CreatedAt: 1704067200,
					PushedAt:  1704153600,
				},
			},
			wantErr: false,
		},
		{
			name:   "inspect with pushed by - table format",
			format: cli.OutputFormatTable,
			req: &InspectRequest{
				Reference: "myrepo/myimage:v4.0",
			},
			resp: &InspectResult{
				Manifest: &ImageManifest{
					Reference: "myrepo/myimage:v4.0",
					Digest:    "sha256:pushedby123",
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					SchemaVer: 2,
					PushedBy:  "admin@example.com",
					CreatedAt: 1704067200,
					PushedAt:  1704153600,
				},
			},
			wantErr: false,
		},
		{
			name:   "inspect - JSON format",
			format: cli.OutputFormatJSON,
			req: &InspectRequest{
				Reference: "myrepo/myimage:v1.0",
			},
			resp: &InspectResult{
				Manifest: &ImageManifest{
					Reference: "myrepo/myimage:v1.0",
					Digest:    "sha256:json123",
				},
			},
			wantErr: false,
		},
		{
			name:   "inspect - YAML format",
			format: cli.OutputFormatYAML,
			req: &InspectRequest{
				Reference: "myrepo/myimage:v1.0",
			},
			resp: &InspectResult{
				Manifest: &ImageManifest{
					Reference: "myrepo/myimage:v1.0",
					Digest:    "sha256:yaml123",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockRegistryClient{
				InspectFunc: func(ctx context.Context, req *InspectRequest) (*InspectResult, error) {
					return tt.resp, nil
				},
			}

			printer := newMockPrinter()

			exec := &CommandExecutor{
				Client:       mockClient,
				Printer:      printer,
				Ctx:          context.Background(),
				OutputFormat: tt.format,
			}

			err := executeInspect(exec, tt.req)

			if (err != nil) != tt.wantErr {
				t.Errorf("executeInspect() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecuteInspect_NilManifest(t *testing.T) {
	mockClient := &MockRegistryClient{
		InspectFunc: func(ctx context.Context, req *InspectRequest) (*InspectResult, error) {
			return &InspectResult{Manifest: nil}, nil
		},
	}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &InspectRequest{Reference: "myrepo/myimage:v1.0"}
	err := executeInspect(exec, req)

	if err != nil {
		t.Errorf("unexpected error for nil manifest: %v", err)
	}
}

func TestExecuteInspect_InvalidImageReference(t *testing.T) {
	mockClient := &MockRegistryClient{}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &InspectRequest{Reference: ""}
	err := executeInspect(exec, req)

	if err == nil {
		t.Error("expected error for empty reference")
	}
	if _, ok := err.(ErrInvalidImageReference); !ok {
		t.Errorf("expected ErrInvalidImageReference, got %T: %v", err, err)
	}
}

func TestExecuteInspect_ClientError(t *testing.T) {
	expectedErr := errors.New("image not found")
	mockClient := &MockRegistryClient{
		InspectFunc: func(ctx context.Context, req *InspectRequest) (*InspectResult, error) {
			return nil, expectedErr
		},
	}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &InspectRequest{Reference: "myrepo/myimage:v1.0"}

	err := executeInspect(exec, req)

	if err == nil {
		t.Error("expected error for client failure")
	}
	if _, ok := err.(ErrInspectFailed); !ok {
		t.Errorf("expected ErrInspectFailed, got %T", err)
	}
}

func TestPrintInspectResponse_InvalidFormat(t *testing.T) {
	printer := newMockPrinter()
	resp := &InspectResult{
		Manifest: &ImageManifest{
			Reference: "myrepo/myimage:v1.0",
		},
	}

	err := printInspectResponse(printer, "invalid", resp, false, false, false)

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestPrintInspectResponse_PrinterError(t *testing.T) {
	expectedErr := errors.New("printer error")
	printer := &MockPrinter{
		PrintFunc: func(v interface{}) error {
			return expectedErr
		},
	}
	resp := &InspectResult{
		Manifest: &ImageManifest{
			Reference: "myrepo/myimage:v1.0",
		},
	}

	err := printInspectResponse(printer, cli.OutputFormatJSON, resp, false, false, false)

	if err == nil {
		t.Error("expected error from printer")
	}
	if err != expectedErr {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

// Status Tests

func TestExecuteStatus_Success(t *testing.T) {
	tests := []struct {
		name    string
		format  cli.OutputFormat
		req     *StatusRequest
		resp    *StatusResult
		wantErr bool
	}{
		{
			name:   "basic status - table format",
			format: cli.OutputFormatTable,
			req:    &StatusRequest{},
			resp: &StatusResult{
				Status: &RegistryStatus{
					Healthy:  true,
					Version:  "1.0.0",
					Endpoint: "https://registry.example.com:5000",
					Uptime:   86400,
					Storage: &StorageStatus{
						Backend:    "filesystem",
						Healthy:    true,
						UsedBytes:  1073741824,
						TotalBytes: 10737418240,
						ImageCount: 100,
						LayerCount: 500,
						BlobCount:  1000,
					},
					Attestation: &AttestationStatus{
						Enabled:        true,
						Required:       true,
						PolicyEngine:   "OPA",
						PolicyEndpoint: "http://localhost:8181",
						PolicyHealthy:  true,
					},
					Encryption: &EncryptionStatus{
						Enabled:           true,
						KeyManagement:     "KMS",
						DefaultKeyID:      "default-key-123",
						EncryptedImages:   50,
						UnencryptedImages: 50,
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "status with metrics - table format",
			format: cli.OutputFormatTable,
			req: &StatusRequest{
				ShowMetrics: true,
			},
			resp: &StatusResult{
				Status: &RegistryStatus{
					Healthy:  true,
					Version:  "1.0.0",
					Endpoint: "https://registry.example.com:5000",
					Uptime:   172800,
					Metrics: &RegistryMetrics{
						PushCount:      1000,
						PullCount:      5000,
						DeleteCount:    100,
						RequestsPerSec: 10.5,
						AvgResponseMs:  25.3,
						ActivePushes:   2,
						ActivePulls:    5,
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "status unhealthy - table format",
			format: cli.OutputFormatTable,
			req:    &StatusRequest{},
			resp: &StatusResult{
				Status: &RegistryStatus{
					Healthy:  false,
					Version:  "1.0.0",
					Endpoint: "https://registry.example.com:5000",
					Uptime:   0,
				},
			},
			wantErr: false,
		},
		{
			name:   "status with storage percentage - table format",
			format: cli.OutputFormatTable,
			req: &StatusRequest{
				ShowStorage: true,
			},
			resp: &StatusResult{
				Status: &RegistryStatus{
					Healthy:  true,
					Version:  "1.0.0",
					Endpoint: "https://registry.example.com:5000",
					Uptime:   86400,
					Storage: &StorageStatus{
						Backend:    "s3",
						Healthy:    true,
						UsedBytes:  5368709120,
						TotalBytes: 10737418240,
						ImageCount: 200,
						LayerCount: 1000,
						BlobCount:  2000,
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "status - JSON format",
			format: cli.OutputFormatJSON,
			req:    &StatusRequest{},
			resp: &StatusResult{
				Status: &RegistryStatus{
					Healthy:  true,
					Version:  "1.0.0",
					Endpoint: "https://registry.example.com:5000",
				},
			},
			wantErr: false,
		},
		{
			name:   "status - YAML format",
			format: cli.OutputFormatYAML,
			req:    &StatusRequest{},
			resp: &StatusResult{
				Status: &RegistryStatus{
					Healthy:  true,
					Version:  "1.0.0",
					Endpoint: "https://registry.example.com:5000",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockRegistryClient{
				StatusFunc: func(ctx context.Context, req *StatusRequest) (*StatusResult, error) {
					return tt.resp, nil
				},
			}

			printer := newMockPrinter()

			exec := &CommandExecutor{
				Client:       mockClient,
				Printer:      printer,
				Ctx:          context.Background(),
				OutputFormat: tt.format,
			}

			err := executeStatus(exec, tt.req)

			if (err != nil) != tt.wantErr {
				t.Errorf("executeStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecuteStatus_NilStatus(t *testing.T) {
	mockClient := &MockRegistryClient{
		StatusFunc: func(ctx context.Context, req *StatusRequest) (*StatusResult, error) {
			return &StatusResult{Status: nil}, nil
		},
	}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &StatusRequest{}
	err := executeStatus(exec, req)

	if err != nil {
		t.Errorf("unexpected error for nil status: %v", err)
	}
}

func TestExecuteStatus_ClientError(t *testing.T) {
	expectedErr := errors.New("connection refused")
	mockClient := &MockRegistryClient{
		StatusFunc: func(ctx context.Context, req *StatusRequest) (*StatusResult, error) {
			return nil, expectedErr
		},
	}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &StatusRequest{}

	err := executeStatus(exec, req)

	if err == nil {
		t.Error("expected error for client failure")
	}
	if _, ok := err.(ErrStatusFailed); !ok {
		t.Errorf("expected ErrStatusFailed, got %T", err)
	}
}

func TestPrintStatusResponse_InvalidFormat(t *testing.T) {
	printer := newMockPrinter()
	resp := &StatusResult{
		Status: &RegistryStatus{
			Healthy: true,
		},
	}

	err := printStatusResponse(printer, "invalid", resp, false, false, false, false)

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestPrintStatusResponse_PrinterError(t *testing.T) {
	expectedErr := errors.New("printer error")
	printer := &MockPrinter{
		PrintFunc: func(v interface{}) error {
			return expectedErr
		},
	}
	resp := &StatusResult{
		Status: &RegistryStatus{
			Healthy: true,
		},
	}

	err := printStatusResponse(printer, cli.OutputFormatJSON, resp, false, false, false, false)

	if err == nil {
		t.Error("expected error from printer")
	}
	if err != expectedErr {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

// Test inspect with layers but no showLayers flag
func TestPrintInspectTableTestable_LayersWithoutFlag(t *testing.T) {
	printer := newMockPrinter()
	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Layers: []*LayerInfo{
			{
				Digest:    "sha256:layer1",
				Size:      512000,
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
			},
			{
				Digest:    "sha256:layer2",
				Size:      256000,
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
			},
		},
	}

	err := printInspectTableTestable(printer, manifest, false, false, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test signature section with unsigned signature
func TestPrintInspectTableTestable_UnsignedSignature(t *testing.T) {
	printer := newMockPrinter()
	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Signature: &SignatureInfo{
			Signed: false,
			Valid:  false,
		},
	}

	err := printInspectTableTestable(printer, manifest, false, true, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test encryption section with unencrypted image
func TestPrintInspectTableTestable_UnencryptedEncryption(t *testing.T) {
	printer := newMockPrinter()
	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Encryption: &EncryptionInfo{
			Encrypted: false,
		},
	}

	err := printInspectTableTestable(printer, manifest, false, false, true)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test status with attestation flags
func TestExecuteStatus_ShowAttestation(t *testing.T) {
	mockClient := &MockRegistryClient{
		StatusFunc: func(ctx context.Context, req *StatusRequest) (*StatusResult, error) {
			return &StatusResult{
				Status: &RegistryStatus{
					Healthy:  true,
					Version:  "1.0.0",
					Endpoint: "https://registry.example.com:5000",
					Uptime:   86400,
					Attestation: &AttestationStatus{
						Enabled:        true,
						Required:       false,
						PolicyEngine:   "OPA",
						PolicyEndpoint: "http://localhost:8181",
						PolicyHealthy:  true,
					},
				},
			}, nil
		},
	}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &StatusRequest{ShowAttestation: true}
	err := executeStatus(exec, req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test status with encryption flags
func TestExecuteStatus_ShowEncryption(t *testing.T) {
	mockClient := &MockRegistryClient{
		StatusFunc: func(ctx context.Context, req *StatusRequest) (*StatusResult, error) {
			return &StatusResult{
				Status: &RegistryStatus{
					Healthy:  true,
					Version:  "1.0.0",
					Endpoint: "https://registry.example.com:5000",
					Uptime:   86400,
					Encryption: &EncryptionStatus{
						Enabled:           true,
						KeyManagement:     "KMS",
						DefaultKeyID:      "key-123",
						EncryptedImages:   100,
						UnencryptedImages: 50,
					},
				},
			}, nil
		},
	}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &StatusRequest{ShowEncryption: true}
	err := executeStatus(exec, req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test status with all flags enabled
func TestExecuteStatus_AllFlags(t *testing.T) {
	mockClient := &MockRegistryClient{
		StatusFunc: func(ctx context.Context, req *StatusRequest) (*StatusResult, error) {
			return &StatusResult{
				Status: &RegistryStatus{
					Healthy:  true,
					Version:  "1.0.0",
					Endpoint: "https://registry.example.com:5000",
					Uptime:   86400,
					Storage: &StorageStatus{
						Backend:    "s3",
						Healthy:    true,
						UsedBytes:  1000000,
						TotalBytes: 10000000,
						ImageCount: 50,
						LayerCount: 200,
						BlobCount:  500,
					},
					Attestation: &AttestationStatus{
						Enabled:       true,
						Required:      true,
						PolicyEngine:  "OPA",
						PolicyHealthy: true,
					},
					Encryption: &EncryptionStatus{
						Enabled:           true,
						KeyManagement:     "KMS",
						EncryptedImages:   30,
						UnencryptedImages: 20,
					},
					Metrics: &RegistryMetrics{
						PushCount:      100,
						PullCount:      500,
						DeleteCount:    10,
						RequestsPerSec: 5.5,
						AvgResponseMs:  15.2,
						ActivePushes:   1,
						ActivePulls:    3,
					},
				},
			}, nil
		},
	}
	printer := newMockPrinter()

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	req := &StatusRequest{
		ShowMetrics:     true,
		ShowStorage:     true,
		ShowAttestation: true,
		ShowEncryption:  true,
	}
	err := executeStatus(exec, req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test layer table print error
func TestPrintInspectTableTestable_LayerPrintError(t *testing.T) {
	expectedErr := errors.New("table print error")
	printer := &MockPrinter{
		PrintFunc: func(v interface{}) error {
			return expectedErr
		},
	}
	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Layers: []*LayerInfo{
			{
				Digest:    "sha256:layer1",
				Size:      512000,
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
			},
		},
	}

	err := printInspectTableTestable(printer, manifest, true, false, false)
	if err == nil {
		t.Error("expected error from layer table print")
	}
	if err != expectedErr {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

// Test manifest without config
func TestPrintInspectTableTestable_NilConfig(t *testing.T) {
	printer := newMockPrinter()
	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Config:    nil,
	}

	err := printInspectTableTestable(printer, manifest, false, false, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test storage without total bytes (no percentage calculation)
func TestPrintStatusTableTestable_StorageNoTotal(t *testing.T) {
	printer := newMockPrinter()
	status := &RegistryStatus{
		Healthy:  true,
		Version:  "1.0.0",
		Endpoint: "https://registry.example.com:5000",
		Uptime:   86400,
		Storage: &StorageStatus{
			Backend:    "s3",
			Healthy:    true,
			UsedBytes:  1000000,
			TotalBytes: 0, // No total - percentage not calculated
			ImageCount: 50,
			LayerCount: 200,
			BlobCount:  500,
		},
	}

	err := printStatusTableTestable(printer, status, false, true, false, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test attestation without policy engine and endpoint
func TestPrintStatusTableTestable_AttestationMinimal(t *testing.T) {
	printer := newMockPrinter()
	status := &RegistryStatus{
		Healthy:  true,
		Version:  "1.0.0",
		Endpoint: "https://registry.example.com:5000",
		Uptime:   86400,
		Attestation: &AttestationStatus{
			Enabled:        false,
			Required:       false,
			PolicyEngine:   "",
			PolicyEndpoint: "",
			PolicyHealthy:  false,
		},
	}

	err := printStatusTableTestable(printer, status, false, false, true, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test encryption without key management and default key
func TestPrintStatusTableTestable_EncryptionMinimal(t *testing.T) {
	printer := newMockPrinter()
	status := &RegistryStatus{
		Healthy:  true,
		Version:  "1.0.0",
		Endpoint: "https://registry.example.com:5000",
		Uptime:   86400,
		Encryption: &EncryptionStatus{
			Enabled:           false,
			KeyManagement:     "",
			DefaultKeyID:      "",
			EncryptedImages:   0,
			UnencryptedImages: 0,
		},
	}

	err := printStatusTableTestable(printer, status, false, false, false, true)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test CommandExecutor struct fields
func TestCommandExecutor_Fields(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockRegistryClient{}
	printer := newMockPrinter()
	var output bytes.Buffer

	exec := &CommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          ctx,
		OutputFormat: cli.OutputFormatJSON,
		Output:       &output,
	}

	if exec.Client != mockClient {
		t.Error("Client not set correctly")
	}
	if exec.Printer != printer {
		t.Error("Printer not set correctly")
	}
	if exec.Ctx != ctx {
		t.Error("Ctx not set correctly")
	}
	if exec.OutputFormat != cli.OutputFormatJSON {
		t.Error("OutputFormat not set correctly")
	}
	if exec.Output != &output {
		t.Error("Output not set correctly")
	}
}

// Test request struct fields
func TestPushRequest_Fields(t *testing.T) {
	req := &PushRequest{
		Reference:    "myrepo/myimage:v1.0",
		Encrypt:      true,
		KeyID:        "key-123",
		Sign:         true,
		SigningKeyID: "signing-key",
		Overwrite:    true,
	}

	if req.Reference != "myrepo/myimage:v1.0" {
		t.Error("Reference not set correctly")
	}
	if !req.Encrypt {
		t.Error("Encrypt not set correctly")
	}
	if req.KeyID != "key-123" {
		t.Error("KeyID not set correctly")
	}
	if !req.Sign {
		t.Error("Sign not set correctly")
	}
	if req.SigningKeyID != "signing-key" {
		t.Error("SigningKeyID not set correctly")
	}
	if !req.Overwrite {
		t.Error("Overwrite not set correctly")
	}
}

func TestPullRequest_Fields(t *testing.T) {
	req := &PullRequest{
		Reference: "myrepo/myimage:v1.0",
		Decrypt:   true,
		Verify:    true,
		Platform:  "linux/amd64",
	}

	if req.Reference != "myrepo/myimage:v1.0" {
		t.Error("Reference not set correctly")
	}
	if !req.Decrypt {
		t.Error("Decrypt not set correctly")
	}
	if !req.Verify {
		t.Error("Verify not set correctly")
	}
	if req.Platform != "linux/amd64" {
		t.Error("Platform not set correctly")
	}
}

func TestListRequest_Fields(t *testing.T) {
	req := &ListRequest{
		Repository:    "myrepo",
		Prefix:        "myimage",
		Limit:         100,
		Cursor:        "cursor-123",
		ShowEncrypted: true,
		SortBy:        "created",
		SortDesc:      true,
	}

	if req.Repository != "myrepo" {
		t.Error("Repository not set correctly")
	}
	if req.Prefix != "myimage" {
		t.Error("Prefix not set correctly")
	}
	if req.Limit != 100 {
		t.Error("Limit not set correctly")
	}
	if req.Cursor != "cursor-123" {
		t.Error("Cursor not set correctly")
	}
	if !req.ShowEncrypted {
		t.Error("ShowEncrypted not set correctly")
	}
	if req.SortBy != "created" {
		t.Error("SortBy not set correctly")
	}
	if !req.SortDesc {
		t.Error("SortDesc not set correctly")
	}
}

func TestDeleteRequest_Fields(t *testing.T) {
	req := &DeleteRequest{
		Reference:    "myrepo/myimage:v1.0",
		Force:        true,
		DryRun:       true,
		KeepUntagged: true,
	}

	if req.Reference != "myrepo/myimage:v1.0" {
		t.Error("Reference not set correctly")
	}
	if !req.Force {
		t.Error("Force not set correctly")
	}
	if !req.DryRun {
		t.Error("DryRun not set correctly")
	}
	if !req.KeepUntagged {
		t.Error("KeepUntagged not set correctly")
	}
}

func TestInspectRequest_Fields(t *testing.T) {
	req := &InspectRequest{
		Reference:      "myrepo/myimage:v1.0",
		ShowLayers:     true,
		ShowSignature:  true,
		ShowEncryption: true,
		RawManifest:    true,
	}

	if req.Reference != "myrepo/myimage:v1.0" {
		t.Error("Reference not set correctly")
	}
	if !req.ShowLayers {
		t.Error("ShowLayers not set correctly")
	}
	if !req.ShowSignature {
		t.Error("ShowSignature not set correctly")
	}
	if !req.ShowEncryption {
		t.Error("ShowEncryption not set correctly")
	}
	if !req.RawManifest {
		t.Error("RawManifest not set correctly")
	}
}

func TestStatusRequest_Fields(t *testing.T) {
	req := &StatusRequest{
		ShowMetrics:     true,
		ShowStorage:     true,
		ShowAttestation: true,
		ShowEncryption:  true,
	}

	if !req.ShowMetrics {
		t.Error("ShowMetrics not set correctly")
	}
	if !req.ShowStorage {
		t.Error("ShowStorage not set correctly")
	}
	if !req.ShowAttestation {
		t.Error("ShowAttestation not set correctly")
	}
	if !req.ShowEncryption {
		t.Error("ShowEncryption not set correctly")
	}
}
