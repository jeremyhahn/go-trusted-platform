package mcp

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// TestServer_ListRequiresPrincipal pins #414 item 1: tools/list and
// resources/list answer only an authenticated caller, as the REST stack
// answers the equivalent with 401. An anonymous client gets the
// AuthenticationRequired code, a rejected token the InvalidToken code.
func TestServer_ListRequiresPrincipal(t *testing.T) {
	methods := []string{"tools/list", "resources/list"}

	cases := []struct {
		name     string
		backend  AuthManager
		token    string
		wantCode int // 0 means the list is returned
	}{
		{name: "no backend, no token", backend: nil, token: "", wantCode: mcpwire.AuthenticationRequired},
		{name: "backend, no token", backend: &mockAuthManager{}, token: "", wantCode: mcpwire.AuthenticationRequired},
		{
			name: "backend, invalid token",
			backend: &mockAuthManager{validateFunc: func(context.Context, string) (bool, error) {
				return false, nil
			}},
			token:    "bad-token",
			wantCode: mcpwire.InvalidToken,
		},
		{name: "backend, valid token", backend: &mockAuthManager{}, token: "good-token", wantCode: 0},
	}

	for _, method := range methods {
		for _, tc := range cases {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				server := NewServer(newMockServiceProvider(), DefaultConfig(), newTestLogger())
				if tc.backend != nil {
					server.SetAuthorizationService(nil, tc.backend)
				}
				ctx := context.Background()
				if tc.token != "" {
					ctx = ContextWithToken(ctx, tc.token)
				}

				resp := server.handleRequest(ctx, &mcpwire.JSONRPCRequest{
					JSONRPC: "2.0",
					ID:      1,
					Method:  method,
				})

				if tc.wantCode != 0 {
					if resp.Error == nil {
						t.Fatalf("%s answered %s with a result, want error code %d", method, tc.name, tc.wantCode)
					}
					if resp.Error.Code != tc.wantCode {
						t.Fatalf("error code = %d, want %d (%s)", resp.Error.Code, tc.wantCode, resp.Error.Message)
					}
					return
				}

				if resp.Error != nil {
					t.Fatalf("unexpected error: %v", resp.Error)
				}
				result, ok := resp.Result.(map[string]interface{})
				if !ok {
					t.Fatal("result is not a map")
				}
				switch method {
				case "tools/list":
					if tools, _ := result["tools"].([]mcpwire.ToolDefinition); len(tools) == 0 {
						t.Error("tools should not be empty")
					}
				case "resources/list":
					if res, _ := result["resources"].([]mcpwire.ResourceDefinition); len(res) == 0 {
						t.Error("resources should not be empty")
					}
				}
			})
		}
	}
}
