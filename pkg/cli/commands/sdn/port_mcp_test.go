package sdn

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// mcpToolCall is one tools/call the MCP stand-in received.
type mcpToolCall struct {
	Name      string
	Arguments map[string]interface{}
}

// mcpStandIn serves the MCP JSON-RPC handshake and answers each tools/call
// with the result named for the tool. It returns CLI flags whose context
// reaches it over MCP.
func mcpStandIn(t *testing.T, results map[string]interface{}, calls *[]mcpToolCall) *cli.CommonFlags {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req mcpwire.JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		resp := mcpwire.JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
		switch req.Method {
		case "initialize":
			resp.Result = map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"serverInfo":      map[string]string{"name": "test", "version": "1.0"},
				"capabilities":    map[string]interface{}{},
			}
		case "tools/call":
			params, _ := req.Params.(map[string]interface{})
			name, _ := params["name"].(string)
			args, _ := params["arguments"].(map[string]interface{})
			*calls = append(*calls, mcpToolCall{Name: name, Arguments: args})
			result, err := mcpwire.NewCallToolResult(results[name])
			if err != nil {
				t.Errorf("encode %s output: %v", name, err)
			}
			resp.Result = result
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	return &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		GetContext: func() (*cli.Context, error) {
			return &cli.Context{
				Name:     "mcp-stand-in",
				Type:     cli.ContextTypeRemote,
				Protocol: "mcp",
				Remote:   &cli.RemoteContext{Server: server.URL},
			}, nil
		},
	}
}

// TestRunPortSetState_OverMCP checks port set-state reaches the
// sdn_set_port_state tool with its arguments named as the tool reads them.
func TestRunPortSetState_OverMCP(t *testing.T) {
	var calls []mcpToolCall
	flags := mcpStandIn(t, map[string]interface{}{
		"sdn_set_port_state": map[string]interface{}{
			"success": true,
			"port":    map[string]interface{}{"id": "eth1", "bridge_id": "br0"},
		},
	}, &calls)

	err := runPortSetState(flags, &platformv1.SetPortStateRequest{
		BridgeId: "br0", PortId: "eth1", AdminState: "down", IngressRate: 1000,
	})
	if err != nil {
		t.Fatalf("runPortSetState: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "sdn_set_port_state" {
		t.Fatalf("calls = %+v, want one sdn_set_port_state", calls)
	}
	args := calls[0].Arguments
	if args["bridge_name"] != "br0" || args["port_name"] != "eth1" || args["state"] != "down" ||
		args["ingress_rate"] != "1000" {
		t.Errorf("args = %+v", args)
	}
}

// TestRunPortSetState_OverMCP_MalformedReply checks a reply the port cannot
// be decoded from surfaces as the command's operation error.
func TestRunPortSetState_OverMCP_MalformedReply(t *testing.T) {
	var calls []mcpToolCall
	flags := mcpStandIn(t, map[string]interface{}{
		"sdn_set_port_state": map[string]interface{}{"success": true, "port": "eth1"},
	}, &calls)

	err := runPortSetState(flags, &platformv1.SetPortStateRequest{BridgeId: "br0", PortId: "eth1", AdminState: "up"})

	var opErr *cli.ErrOperationFailed
	if !errors.As(err, &opErr) || opErr.Operation != "port set-state" {
		t.Fatalf("err = %v, want ErrOperationFailed for port set-state", err)
	}
	if len(calls) != 1 {
		t.Errorf("calls = %+v, want the tool reached once", calls)
	}
}
