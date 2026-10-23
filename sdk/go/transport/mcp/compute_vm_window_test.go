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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// vm_stop and vm_reboot wait for the daemon's reply window, not the client's
// 5-second default: a graceful stop answers only after the guest powers down.
func TestReplyWindowStopAndReboot(t *testing.T) {
	tests := []struct {
		name   string
		method string
		args   interface{}
		want   time.Duration
	}{
		{"graceful stop", platformv1.ComputeService_StopVM_FullMethodName, &platformv1.StopVMRequest{Id: "vm-1"}, time.Minute},
		{"stop with timeout", platformv1.ComputeService_StopVM_FullMethodName, &platformv1.StopVMRequest{Id: "vm-1", TimeoutSeconds: 120}, 150 * time.Second},
		{"forced stop", platformv1.ComputeService_StopVM_FullMethodName, &platformv1.StopVMRequest{Id: "vm-1", Force: true}, 30 * time.Second},
		{"graceful reboot", platformv1.ComputeService_RebootVM_FullMethodName, &platformv1.RebootVMRequest{Id: "vm-1"}, time.Minute},
		{"forced reboot", platformv1.ComputeService_RebootVM_FullMethodName, &platformv1.RebootVMRequest{Id: "vm-1", Force: true}, 30 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := replyWindow(tt.method, tt.args); got != tt.want {
				t.Errorf("replyWindow() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Every other method, and a request of the wrong type, keeps the client's
// timeout.
func TestReplyWindowFallsBackToClientTimeout(t *testing.T) {
	tests := []struct {
		name   string
		method string
		args   interface{}
	}{
		{"unmapped method", platformv1.ComputeService_StartVM_FullMethodName, &platformv1.StartVMRequest{Id: "vm-1"}},
		{"stop with a reboot request", platformv1.ComputeService_StopVM_FullMethodName, &platformv1.RebootVMRequest{Id: "vm-1"}},
		{"reboot with no request", platformv1.ComputeService_RebootVM_FullMethodName, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := replyWindow(tt.method, tt.args); got != 0 {
				t.Errorf("replyWindow() = %v, want 0", got)
			}
		})
	}
}
