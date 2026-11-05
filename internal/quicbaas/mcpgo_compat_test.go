package quicbaas

// mcp-go v1.4.0 compatibility for the pinned go-quicbaas MCP transport.
//
// The platform links mark3labs/mcp-go through go-quicbaas/sdk/go (the
// ModuleMCPServer alias) and go-quicbaas/sdk/go/transport/mcp (the SDK's MCP
// client). These tests run that pinned client against a real mcp-go v1.4.0
// Streamable HTTP server, so a major-version bump of mcp-go is proven against
// the contracts the client relies on: initialize, tools/call, the
// quicbaas_login bearer flow, tool errors and session teardown.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport"
	sdkmcp "github.com/jeremyhahn/go-quicbaas/sdk/go/transport/mcp"
	mcpclient "github.com/mark3labs/mcp-go/client"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// mcpCompatDeadline bounds every wait on a server-side event.
const mcpCompatDeadline = 5 * time.Second

// mcpCompatEvents records server hook events through buffered channels.
type mcpCompatEvents struct {
	initialized  chan struct{}
	unregistered chan string
}

func newMCPCompatEvents() *mcpCompatEvents {
	return &mcpCompatEvents{
		initialized:  make(chan struct{}, 16),
		unregistered: make(chan string, 16),
	}
}

func (e *mcpCompatEvents) hooks() *mcpserver.Hooks {
	hooks := &mcpserver.Hooks{}
	hooks.AddAfterInitialize(func(context.Context, any, *mcpgo.InitializeRequest, *mcpgo.InitializeResult) {
		e.initialized <- struct{}{}
	})
	hooks.AddOnUnregisterSession(func(_ context.Context, session mcpserver.ClientSession) {
		e.unregistered <- session.SessionID()
	})
	return hooks
}

// newMCPCompatServer starts a real mcp-go Streamable HTTP server for srv.
func newMCPCompatServer(t *testing.T, srv *mcpserver.MCPServer) *httptest.Server {
	t.Helper()
	httpSrv := httptest.NewServer(mcpserver.NewStreamableHTTPServer(srv))
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// newMCPCompatTransport builds the pinned SDK MCP client against httpSrv.
func newMCPCompatTransport(t *testing.T, httpSrv *httptest.Server, opts ...sdkmcp.Option) *sdkmcp.Transport {
	t.Helper()
	tr, err := sdkmcp.New(&transport.Config{Address: httpSrv.URL, Timeout: mcpCompatDeadline}, opts...)
	if err != nil {
		t.Fatalf("sdkmcp.New: %v", err)
	}
	t.Cleanup(func() {
		if err := tr.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return tr
}

// qrdbGetTool declares qrdb_get with a required string "key".
func qrdbGetTool() mcpgo.Tool {
	return mcpgo.NewTool("qrdb_get",
		mcpgo.WithDescription("compat get"),
		mcpgo.WithString("key", mcpgo.Required()),
	)
}

// echoResult returns a JSON text result echoing key.
func echoResult(t *testing.T, key string) *mcpgo.CallToolResult {
	body, err := json.Marshal(map[string]string{"key": key, "value": "v-" + key})
	if err != nil {
		t.Errorf("marshal echo: %v", err)
		return mcpgo.NewToolResultError(err.Error())
	}
	return mcpgo.NewToolResultText(string(body))
}

// requestGet runs quicbaas.KV/Get (mapped to qrdb_get) for key.
func requestGet(ctx context.Context, tr *sdkmcp.Transport, key string) (interface{}, error) {
	return tr.Request(ctx, "quicbaas.KV", "Get", map[string]interface{}{"key": key})
}

func requireEcho(t *testing.T, resp interface{}, key string) {
	t.Helper()
	m, ok := resp.(map[string]interface{})
	if !ok {
		t.Fatalf("response is %T, want map", resp)
	}
	if m["key"] != key || m["value"] != "v-"+key {
		t.Fatalf("response = %v, want key %q value %q", m, key, "v-"+key)
	}
}

func TestMCPGoCompat_RoundTripAndSessionReuse(t *testing.T) {
	events := newMCPCompatEvents()
	srv := mcpserver.NewMCPServer("compat", "1.0.0", mcpserver.WithHooks(events.hooks()))
	sessions := make(chan string, 4)
	srv.AddTool(qrdbGetTool(), func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
		session := mcpserver.ClientSessionFromContext(ctx)
		if session == nil {
			sessions <- ""
		} else {
			sessions <- session.SessionID()
		}
		key, err := req.RequireString("key")
		if err != nil {
			return mcpgo.NewToolResultError(err.Error()), nil
		}
		return echoResult(t, key), nil
	})
	tr := newMCPCompatTransport(t, newMCPCompatServer(t, srv))

	ctx := context.Background()
	for _, key := range []string{"k1", "k2"} {
		resp, err := requestGet(ctx, tr, key)
		if err != nil {
			t.Fatalf("Request(%s): %v", key, err)
		}
		requireEcho(t, resp, key)
	}

	first, second := <-sessions, <-sessions
	if first == "" {
		t.Fatal("tool handler saw no client session")
	}
	if first != second {
		t.Fatalf("calls ran in sessions %q and %q, want one session", first, second)
	}
	select {
	case <-events.initialized:
	case <-time.After(mcpCompatDeadline):
		t.Fatal("after-initialize hook never fired")
	}
	select {
	case <-events.initialized:
		t.Fatal("after-initialize hook fired twice; the session was not reused")
	default:
	}
}

func TestMCPGoCompat_AuthBearerReachesServer(t *testing.T) {
	const token = "compat-token-123"
	srv := mcpserver.NewMCPServer("compat", "1.0.0")
	srv.AddTool(mcpgo.NewTool("quicbaas_login",
		mcpgo.WithString("username", mcpgo.Required()),
		mcpgo.WithString("password", mcpgo.Required()),
	), func(_ context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
		if req.GetString("username", "") != "admin" || req.GetString("password", "") != "secret" {
			return mcpgo.NewToolResultError("bad credentials"), nil
		}
		return mcpgo.NewToolResultText(`{"access_token":"` + token + `"}`), nil
	})
	authHeaders := make(chan string, 4)
	srv.AddTool(qrdbGetTool(), func(_ context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
		authHeaders <- req.Header.Get("Authorization")
		return echoResult(t, req.GetString("key", "")), nil
	})
	tr := newMCPCompatTransport(t, newMCPCompatServer(t, srv), sdkmcp.WithCredentials("admin", "secret"))

	resp, err := requestGet(context.Background(), tr, "k1")
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	requireEcho(t, resp, "k1")
	if got := <-authHeaders; got != "Bearer "+token {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer "+token)
	}
}

func TestMCPGoCompat_ToolErrorSurfaces(t *testing.T) {
	srv := mcpserver.NewMCPServer("compat", "1.0.0")
	srv.AddTool(qrdbGetTool(), func(context.Context, mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
		return mcpgo.NewToolResultError("boom"), nil
	})
	tr := newMCPCompatTransport(t, newMCPCompatServer(t, srv))

	resp, err := requestGet(context.Background(), tr, "k1")
	if err == nil {
		t.Fatalf("Request returned %v, want the tool error", resp)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error %q does not carry the tool error text", err)
	}
}

func TestMCPGoCompat_CloseEndsSession(t *testing.T) {
	events := newMCPCompatEvents()
	srv := mcpserver.NewMCPServer("compat", "1.0.0", mcpserver.WithHooks(events.hooks()))
	sessions := make(chan string, 1)
	srv.AddTool(qrdbGetTool(), func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
		if session := mcpserver.ClientSessionFromContext(ctx); session != nil {
			sessions <- session.SessionID()
		}
		return echoResult(t, req.GetString("key", "")), nil
	})
	tr, err := sdkmcp.New(&transport.Config{Address: newMCPCompatServer(t, srv).URL, Timeout: mcpCompatDeadline})
	if err != nil {
		t.Fatalf("sdkmcp.New: %v", err)
	}

	ctx := context.Background()
	if _, err := requestGet(ctx, tr, "k1"); err != nil {
		t.Fatalf("Request: %v", err)
	}
	var used string
	select {
	case used = <-sessions:
	default:
		t.Fatal("tool handler saw no client session")
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case ended := <-events.unregistered:
		if ended != used {
			t.Fatalf("unregistered session %q, want %q", ended, used)
		}
	case <-time.After(mcpCompatDeadline):
		t.Fatal("server never unregistered the session after Close")
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := requestGet(ctx, tr, "k2"); err == nil {
		t.Fatal("Request after Close succeeded, want an error")
	}
}

// asModuleServer is the compile-time check that the SDK's ModuleMCPServer
// alias is mcp-go's own server type: it accepts an mcp-go server unconverted.
func asModuleServer(srv *quicbaassdk.ModuleMCPServer) *quicbaassdk.ModuleMCPServer {
	return srv
}

func TestMCPGoCompat_ModuleServerAlias(t *testing.T) {
	srv := asModuleServer(mcpserver.NewMCPServer("compat", "1.0.0"))
	srv.AddTool(qrdbGetTool(), func(_ context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
		return echoResult(t, req.GetString("key", "")), nil
	})
	httpSrv := newMCPCompatServer(t, srv)

	ctx := context.Background()
	client, err := mcpclient.NewStreamableHttpClient(httpSrv.URL)
	if err != nil {
		t.Fatalf("NewStreamableHttpClient: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("client Close: %v", err)
		}
	})
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := client.Initialize(ctx, mcpgo.InitializeRequest{}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	result, err := client.ListTools(ctx, mcpgo.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(result.Tools) != 1 || result.Tools[0].Name != "qrdb_get" {
		t.Fatalf("ListTools = %+v, want only qrdb_get", result.Tools)
	}
	schema := result.Tools[0].InputSchema
	if len(schema.Required) != 1 || schema.Required[0] != "key" {
		t.Fatalf("qrdb_get required = %v, want [key]", schema.Required)
	}
	if _, ok := schema.Properties["key"]; !ok {
		t.Fatalf("qrdb_get properties = %v, want key", schema.Properties)
	}
}
