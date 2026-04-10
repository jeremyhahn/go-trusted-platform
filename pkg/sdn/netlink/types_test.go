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

package netlink

import (
	"strings"
	"testing"
)

func TestTAPConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *TAPConfig
		wantErr bool
		errType ErrorType
	}{
		{
			name: "valid config",
			config: &TAPConfig{
				Name:       "tap0",
				Owner:      1000,
				Group:      1000,
				MultiQueue: false,
				Persist:    false,
				MTU:        1500,
			},
			wantErr: false,
		},
		{
			name: "empty name",
			config: &TAPConfig{
				Name:  "",
				Owner: 1000,
				Group: 1000,
			},
			wantErr: true,
			errType: ErrorTypeInvalidName,
		},
		{
			name: "name too long",
			config: &TAPConfig{
				Name:  "verylonginterfacename",
				Owner: 1000,
				Group: 1000,
			},
			wantErr: true,
			errType: ErrorTypeInvalidName,
		},
		{
			name: "max length name (15 chars)",
			config: &TAPConfig{
				Name:  "tap12345678901",
				Owner: 1000,
				Group: 1000,
			},
			wantErr: false,
		},
		{
			name: "minimal config",
			config: &TAPConfig{
				Name: "tap0",
			},
			wantErr: false,
		},
		{
			name: "with multi-queue",
			config: &TAPConfig{
				Name:       "tap0",
				MultiQueue: true,
			},
			wantErr: false,
		},
		{
			name: "with persist",
			config: &TAPConfig{
				Name:    "tap0",
				Persist: true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				var netlinkErr *NetlinkError
				if err != nil {
					if ne, ok := err.(*NetlinkError); ok {
						netlinkErr = ne
					}
				}

				if netlinkErr == nil {
					t.Errorf("expected NetlinkError, got %T", err)
					return
				}

				if netlinkErr.Type != tt.errType {
					t.Errorf("Error type = %v, want %v", netlinkErr.Type, tt.errType)
				}
			}
		})
	}
}

func TestLinkState_String(t *testing.T) {
	tests := []struct {
		name  string
		state LinkState
		want  string
	}{
		{
			name:  "up state",
			state: LinkStateUp,
			want:  "up",
		},
		{
			name:  "down state",
			state: LinkStateDown,
			want:  "down",
		},
		{
			name:  "unknown state",
			state: LinkStateUnknown,
			want:  "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.state) != tt.want {
				t.Errorf("LinkState = %v, want %v", tt.state, tt.want)
			}
		})
	}
}

func TestTAPConfig_NameLengthBoundary(t *testing.T) {
	// Test exact boundary conditions for name length
	tests := []struct {
		length  int
		wantErr bool
	}{
		{length: 0, wantErr: true},
		{length: 1, wantErr: false},
		{length: 14, wantErr: false},
		{length: 15, wantErr: false},
		{length: 16, wantErr: true},
		{length: 20, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(strings.Repeat("x", tt.length), func(t *testing.T) {
			config := &TAPConfig{
				Name: strings.Repeat("x", tt.length),
			}

			err := config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() with name length %d: error = %v, wantErr %v",
					tt.length, err, tt.wantErr)
			}
		})
	}
}

func TestLinkInfo_Structure(t *testing.T) {
	// Test that LinkInfo has all expected fields
	info := &LinkInfo{
		Index:        1,
		Name:         "test0",
		Type:         "tuntap",
		Flags:        0x1003,
		MTU:          1500,
		HardwareAddr: "00:11:22:33:44:55",
		OperState:    LinkStateUp,
		Master:       0,
	}

	if info.Index != 1 {
		t.Errorf("Index = %d, want 1", info.Index)
	}
	if info.Name != "test0" {
		t.Errorf("Name = %s, want test0", info.Name)
	}
	if info.Type != "tuntap" {
		t.Errorf("Type = %s, want tuntap", info.Type)
	}
	if info.MTU != 1500 {
		t.Errorf("MTU = %d, want 1500", info.MTU)
	}
	if info.OperState != LinkStateUp {
		t.Errorf("OperState = %v, want %v", info.OperState, LinkStateUp)
	}
}

func TestTAPInfo_Structure(t *testing.T) {
	// Test that TAPInfo embeds LinkInfo and has TAP-specific fields
	tapInfo := &TAPInfo{
		LinkInfo: LinkInfo{
			Index:        1,
			Name:         "tap0",
			Type:         "tuntap",
			Flags:        0x1003,
			MTU:          1500,
			HardwareAddr: "00:11:22:33:44:55",
			OperState:    LinkStateUp,
			Master:       0,
		},
		Owner:      1000,
		Group:      1000,
		MultiQueue: true,
		Persist:    false,
	}

	// Test embedded LinkInfo fields
	if tapInfo.Name != "tap0" {
		t.Errorf("Name = %s, want tap0", tapInfo.Name)
	}
	if tapInfo.MTU != 1500 {
		t.Errorf("MTU = %d, want 1500", tapInfo.MTU)
	}

	// Test TAP-specific fields
	if tapInfo.Owner != 1000 {
		t.Errorf("Owner = %d, want 1000", tapInfo.Owner)
	}
	if tapInfo.Group != 1000 {
		t.Errorf("Group = %d, want 1000", tapInfo.Group)
	}
	if !tapInfo.MultiQueue {
		t.Error("MultiQueue = false, want true")
	}
	if tapInfo.Persist {
		t.Error("Persist = true, want false")
	}
}
