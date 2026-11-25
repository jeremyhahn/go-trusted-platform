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

	"github.com/stretchr/testify/assert"
)

// TestSelectIptables checks that iptables-legacy is chosen only when the
// binary exists and its tables load; otherwise plain iptables is used.
func TestSelectIptables(t *testing.T) {
	tests := []struct {
		name         string
		found        bool
		usable       bool
		want         string
		wantUsableCx bool
	}{
		{name: "legacy found and usable", found: true, usable: true, want: "iptables-legacy", wantUsableCx: true},
		{name: "legacy found but not usable", found: true, usable: false, want: "iptables", wantUsableCx: true},
		{name: "legacy missing", found: false, usable: true, want: "iptables", wantUsableCx: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookPath := func(name string) (string, error) {
				assert.Equal(t, "iptables-legacy", name)
				if tt.found {
					return "/usr/sbin/" + name, nil
				}
				return "", errors.New("not found")
			}
			usableCalled := false
			usable := func(cmd string) bool {
				usableCalled = true
				assert.Equal(t, "iptables-legacy", cmd)
				return tt.usable
			}

			got := selectIptables(lookPath, usable)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantUsableCx, usableCalled, "usable called")
		})
	}
}
