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

package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// TestWireClient_RefusalIsNotRetried sends a tool call the server refuses
// through the SDK's MCP wire client and checks the refusal is answered once:
// a refusal is the same answer on every try.
func TestWireClient_RefusalIsNotRetried(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		wantCode int
		wantGRPC codes.Code
	}{
		{"missing token", "", mcpwire.AuthenticationRequired, codes.Unauthenticated},
		{"invalid token", "stolen-token", mcpwire.InvalidToken, codes.Unauthenticated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMgr := &mockAuthManager{
				validateFunc: func(ctx context.Context, token string) (bool, error) {
					return token == "valid-token", nil
				},
			}
			server := NewServer(newMockServiceProvider(), &Config{AuthManager: authMgr}, newTestLogger())

			var attempts atomic.Int32
			handler := server.Handler()
			httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				handler.ServeHTTP(w, r)
			}))
			defer httpServer.Close()

			client, err := mcpwire.NewClient(&mcpwire.ClientConfig{
				ServerAddr: httpServer.URL,
				Timeout:    5 * time.Second,
				MaxRetries: 3,
				RetryDelay: time.Millisecond,
			})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			defer func() { _ = client.Close() }()
			client.SetToken(tt.token)

			_, err = client.CallTool(context.Background(), "vtpm_create", map[string]interface{}{"name": "test"})

			var mcpErr *mcpwire.MCPError
			if !errors.As(err, &mcpErr) {
				t.Fatalf("err = %v, want an MCPError", err)
			}
			if mcpErr.Code != tt.wantCode {
				t.Errorf("code = %d, want %d", mcpErr.Code, tt.wantCode)
			}
			if got := mcpwire.ClassForCode(mcpErr.Code); got != tt.wantGRPC {
				t.Errorf("class = %s, want %s", got, tt.wantGRPC)
			}
			if got := attempts.Load(); got != 1 {
				t.Errorf("attempts = %d, want 1", got)
			}
		})
	}
}
