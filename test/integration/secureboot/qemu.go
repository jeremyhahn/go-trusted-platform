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

//go:build integration

package secureboot

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// ovmfCodeCandidates are the Secure Boot capable OVMF firmware images probed
// in order. Only *.secboot.fd builds enforce signature verification; the
// plain OVMF_CODE images are compiled without SECURE_BOOT_ENABLE.
var ovmfCodeCandidates = []string{
	"/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
	"/usr/share/OVMF/OVMF_CODE.secboot.fd",
	"/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd",
}

// ovmfVarsCandidates are the matching blank (no keys enrolled) variable store
// templates, probed in order.
var ovmfVarsCandidates = []string{
	"/usr/share/OVMF/OVMF_VARS_4M.fd",
	"/usr/share/OVMF/OVMF_VARS.fd",
	"/usr/share/edk2/ovmf/OVMF_VARS.fd",
}

// findOVMF resolves the Secure Boot OVMF code image and the blank VARS
// template, failing with a typed error when neither is installed.
func findOVMF(t *testing.T) (code, vars string) {
	t.Helper()
	for _, c := range ovmfCodeCandidates {
		if _, err := os.Stat(c); err == nil {
			code = c
			break
		}
	}
	for _, v := range ovmfVarsCandidates {
		if _, err := os.Stat(v); err == nil {
			vars = v
			break
		}
	}
	if code == "" || vars == "" {
		t.Fatal(ErrFirmwareNotFound{Searched: append(append([]string{}, ovmfCodeCandidates...), ovmfVarsCandidates...)})
	}
	return code, vars
}

// serialResult reports the outcome of a marker watch.
type serialResult struct {
	// Marker is the first awaited marker observed, or "" on timeout/exit.
	Marker string
	// Output is the full captured serial transcript.
	Output string
}

// runQEMU boots a VM with the given arguments and watches the serial console
// (routed to stdout) for the first occurrence of any of the markers. It
// returns as soon as a marker is seen — killing the VM — or when ctx expires
// or the VM exits, whichever comes first. All waiting is channel-based.
func runQEMU(t *testing.T, ctx context.Context, qemuArgs []string, markers ...string) serialResult {
	t.Helper()

	qemu := requireTool(t, "qemu-system-x86_64", "boot the Secure Boot test VMs")

	cmd := exec.CommandContext(ctx, qemu, qemuArgs...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("qemu stdout pipe: %v", err)
	}
	cmd.Stderr = cmd.Stdout // interleave firmware/QEMU errors into the transcript
	cmd.Cancel = func() error { return cmd.Process.Kill() }

	if err := cmd.Start(); err != nil {
		t.Fatalf("start qemu: %v", err)
	}

	var mu sync.Mutex
	var transcript strings.Builder
	found := make(chan string, 1)
	done := make(chan struct{})

	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		// window keeps the tail of the transcript so markers split across
		// reads are still matched.
		var window string
		for {
			n, readErr := stdout.Read(buf)
			if n > 0 {
				chunk := string(buf[:n])
				mu.Lock()
				transcript.WriteString(chunk)
				mu.Unlock()
				window += chunk
				for _, m := range markers {
					if strings.Contains(window, m) {
						select {
						case found <- m:
						default:
						}
						return
					}
				}
				// Retain enough tail to match the longest marker.
				max := 0
				for _, m := range markers {
					if len(m) > max {
						max = len(m)
					}
				}
				if len(window) > 8192+max {
					window = window[len(window)-max:]
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	var marker string
	select {
	case marker = <-found:
	case <-done:
		// VM exited (or pipe closed) without any marker.
	case <-ctx.Done():
	}

	// Tear the VM down and drain the reader before capturing the transcript.
	_ = cmd.Process.Kill()
	<-done
	_ = cmd.Wait()
	_, _ = io.Copy(io.Discard, stdout)

	mu.Lock()
	out := transcript.String()
	mu.Unlock()
	return serialResult{Marker: marker, Output: out}
}
