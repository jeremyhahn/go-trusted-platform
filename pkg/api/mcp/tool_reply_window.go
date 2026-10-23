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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// toolReplyWindowFunc is how long a tool call with these arguments may take
// to answer.
type toolReplyWindowFunc func(args map[string]interface{}) time.Duration

// toolReplyWindows routes the tools whose reply may legitimately outlast the
// server's RequestTimeout: a stop waits up to the guest's power-down window
// and a reboot waits that long and then starts the VM. Each gets the window
// REST moves its reply deadline to, StopOptions.ReplyWindow
// (docs/compute/api.md).
var toolReplyWindows = map[string]toolReplyWindowFunc{
	"vm_stop":   vmStopReplyWindow,
	"vm_reboot": vmRebootReplyWindow,
}

// vmStopReplyWindow is the window of the stop vm_stop asks for. Arguments
// that do not decode get no window: the tool refuses them itself.
func vmStopReplyWindow(args map[string]interface{}) time.Duration {
	req := &platformv1.StopVMRequest{}
	if err := decodeAppToolArgs(args, req); err != nil {
		return 0
	}
	return compute.StopOptions{
		Force:   req.GetForce(),
		Timeout: time.Duration(req.GetTimeoutSeconds()) * time.Second,
	}.ReplyWindow()
}

// vmRebootReplyWindow is the window of the stop half of the reboot vm_reboot
// asks for; the window's margin covers the start. Arguments that do not
// decode get no window: the tool refuses them itself.
func vmRebootReplyWindow(args map[string]interface{}) time.Duration {
	req := &platformv1.RebootVMRequest{}
	if err := decodeAppToolArgs(args, req); err != nil {
		return 0
	}
	return compute.StopOptions{Force: req.GetForce()}.ReplyWindow()
}

// callTimeout is how long a stdio request may run: the server's
// RequestTimeout, or a tool call's reply window when that is longer. Over
// HTTP the request bounds the call instead (ToolRegistry.ExecuteTool).
func (s *Server) callTimeout(req *mcpwire.JSONRPCRequest) time.Duration {
	timeout := s.config.RequestTimeout
	if req.Method != "tools/call" {
		return timeout
	}
	params, ok := req.Params.(map[string]interface{})
	if !ok {
		return timeout
	}
	name, ok := params["name"].(string)
	if !ok {
		return timeout
	}
	window, ok := toolReplyWindows[name]
	if !ok {
		return timeout
	}
	// Missing arguments decode as the tool's defaults, as the call does.
	var args map[string]interface{}
	if given, ok := params["arguments"].(map[string]interface{}); ok {
		args = given
	}
	return max(timeout, window(args))
}

// stdioContext is the context a stdio request runs under. stdio has no TLS
// connection, so a quote requested over it is refused rather than produced
// unbound.
func (s *Server) stdioContext(req *mcpwire.JSONRPCRequest) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), s.callTimeout(req))
	return channelbind.WithConnectionTLS(ctx, channelbind.TransportMCP, nil), cancel
}
