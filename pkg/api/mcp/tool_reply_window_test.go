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
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// stdioRequestTimeout is the server default the windows are measured against.
const stdioRequestTimeout = 30 * time.Second

func newStdioTimeoutServer() *Server {
	return NewServer(newMockServiceProvider(), &Config{RequestTimeout: stdioRequestTimeout}, newTestLogger())
}

func toolCall(params interface{}) *mcpwire.JSONRPCRequest {
	return &mcpwire.JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params}
}

// A default reboot waits up to 30 seconds for the guest and then starts the
// VM, so over stdio it cannot run under the 30-second RequestTimeout: it gets
// the window REST moves its reply deadline to.
func TestStdioCallTimeoutGivesStopAndRebootTheirReplyWindow(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]interface{}
		want   time.Duration
	}{
		{
			name:   "default reboot",
			params: map[string]interface{}{"name": "vm_reboot", "arguments": map[string]interface{}{"id": "vm-1"}},
			want:   compute.StopOptions{}.ReplyWindow(),
		},
		{
			name:   "reboot without arguments",
			params: map[string]interface{}{"name": "vm_reboot"},
			want:   compute.StopOptions{}.ReplyWindow(),
		},
		{
			name:   "stop with a two-minute window",
			params: map[string]interface{}{"name": "vm_stop", "arguments": map[string]interface{}{"id": "vm-1", "timeout_seconds": 120}},
			want:   compute.StopOptions{Timeout: 2 * time.Minute}.ReplyWindow(),
		},
	}
	server := newStdioTimeoutServer()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := server.callTimeout(toolCall(tc.params))
			if got != tc.want {
				t.Errorf("callTimeout = %v, want %v", got, tc.want)
			}
			if got <= stdioRequestTimeout {
				t.Errorf("callTimeout = %v, want longer than the %v RequestTimeout", got, stdioRequestTimeout)
			}
		})
	}
}

// Every other request, and a stop or reboot whose window is shorter or whose
// arguments the tool will refuse, keeps the server's RequestTimeout.
func TestStdioCallTimeoutKeepsRequestTimeoutOtherwise(t *testing.T) {
	cases := map[string]*mcpwire.JSONRPCRequest{
		"not a tool call":        {JSONRPC: "2.0", ID: 1, Method: "tools/list"},
		"params not an object":   toolCall("vm_reboot"),
		"no tool name":           toolCall(map[string]interface{}{"arguments": map[string]interface{}{"id": "vm-1"}}),
		"tool name not a string": toolCall(map[string]interface{}{"name": 7}),
		"tool without a window":  toolCall(map[string]interface{}{"name": "vm_start", "arguments": map[string]interface{}{"id": "vm-1"}}),
		"arguments that do not decode": toolCall(map[string]interface{}{
			"name": "vm_reboot", "arguments": map[string]interface{}{"id": "vm-1", "no_such_field": true},
		}),
		"forced stop shorter than the timeout": toolCall(map[string]interface{}{
			"name": "vm_stop", "arguments": map[string]interface{}{"id": "vm-1", "force": true},
		}),
	}
	server := newStdioTimeoutServer()
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if got := server.callTimeout(req); got != stdioRequestTimeout {
				t.Errorf("callTimeout = %v, want the RequestTimeout %v", got, stdioRequestTimeout)
			}
		})
	}
}

// The stdio context carries the call's timeout as its deadline and records
// the MCP transport without TLS, so a quote over stdio is still refused.
func TestStdioContextCarriesTheCallTimeoutAndNoTLS(t *testing.T) {
	server := newStdioTimeoutServer()
	req := toolCall(map[string]interface{}{"name": "vm_reboot", "arguments": map[string]interface{}{"id": "vm-1"}})

	before := time.Now()
	ctx, cancel := server.stdioContext(req)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("stdio context has no deadline, want the call's timeout")
	}
	if want := before.Add(compute.StopOptions{}.ReplyWindow()); deadline.Before(want) {
		t.Errorf("deadline %v before the reboot's reply window ends at %v", deadline, want)
	}
	state, transport, recorded := channelbind.ConnectionTLS(ctx)
	if !recorded || transport != channelbind.TransportMCP || state != nil {
		t.Errorf("ConnectionTLS = (%v, %q, %v), want (nil, %q, true)", state, transport, recorded, channelbind.TransportMCP)
	}
}

// The window functions refuse nothing themselves: arguments that do not
// decode get no window, and the tool answers InvalidArgument.
func TestVMReplyWindowsWithUndecodableArgumentsAreZero(t *testing.T) {
	bad := map[string]interface{}{"id": []interface{}{"not", "a", "string"}}
	for name, window := range toolReplyWindows {
		if got := window(bad); got != 0 {
			t.Errorf("%s window = %v for undecodable arguments, want 0", name, got)
		}
	}
}
