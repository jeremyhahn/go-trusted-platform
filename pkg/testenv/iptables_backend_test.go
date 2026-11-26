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

//go:build linux

// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// swapIptablesProbe makes the backend probe answer probed for the test.
func swapIptablesProbe(t *testing.T, probed string) *int {
	t.Helper()
	calls := 0
	orig := iptablesProbe
	iptablesProbe = func() string {
		calls++
		return probed
	}
	t.Cleanup(func() { iptablesProbe = orig })
	return &calls
}

func TestCleanupBackend_UsesTheBackendSetupRecorded(t *testing.T) {
	calls := swapIptablesProbe(t, "iptables")

	linux := &LinuxIsolatedNetwork{iptablesCmd: "iptables-legacy"}
	assert.Equal(t, "iptables-legacy", linux.cleanupIptablesCmd())

	ovsNet := &OVSIsolatedNetwork{iptablesCmd: "iptables-legacy"}
	assert.Equal(t, "iptables-legacy", ovsNet.cleanupIptablesCmd())

	assert.Zero(t, *calls, "cleanup must not re-probe when setup recorded a backend")
}

func TestCleanupBackend_ProbesWhenSetupRecordedNone(t *testing.T) {
	calls := swapIptablesProbe(t, "iptables")

	assert.Equal(t, "iptables", (&LinuxIsolatedNetwork{}).cleanupIptablesCmd())
	assert.Equal(t, "iptables", (&OVSIsolatedNetwork{}).cleanupIptablesCmd())
	assert.Equal(t, 2, *calls)
}

func TestIptablesProbe_ClassifiesUnsupportedTables(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want bool
	}{
		{"missing filter table", "iptables v1.8.7 (legacy): can't initialize iptables table `filter': Table does not exist (do you need to insmod?)\nPerhaps iptables or your kernel needs to be upgraded.", true},
		{"protocol not supported", "iptables v1.8.7 (legacy): can't initialize iptables table `filter': Address family not supported by protocol", true},
		{"xtables lock contention", "Another app is currently holding the xtables lock. Stopped waiting after 5s.", false},
		{"resource temporarily unavailable", "iptables: Resource temporarily unavailable.", false},
		{"generic failure", "exit status 4", false},
		{"empty output", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, iptablesTableUnsupported(tt.out))
		})
	}
}

func TestIptablesProbe_TransientFailureRetriesThenKeepsLegacy(t *testing.T) {
	fail := errors.New("exit status 4")
	tests := []struct {
		name      string
		results   []error
		outs      []string
		want      bool
		wantCalls int
	}{
		{"works first time", []error{nil}, []string{""}, true, 1},
		{"unsupported table stops at once", []error{fail}, []string{"can't initialize iptables table `filter': Table does not exist"}, false, 1},
		{"transient then works", []error{fail, nil}, []string{"Another app is currently holding the xtables lock.", ""}, true, 2},
		{"transient every time keeps legacy", []error{fail, fail, fail}, []string{"xtables lock", "xtables lock", "xtables lock"}, true, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			run := func() ([]byte, error) {
				i := calls
				calls++
				return []byte(tt.outs[i]), tt.results[i]
			}
			assert.Equal(t, tt.want, iptablesUsableWith(run, 3, time.Millisecond))
			assert.Equal(t, tt.wantCalls, calls)
		})
	}
}
