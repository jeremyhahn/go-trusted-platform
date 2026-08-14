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

package cluster

import (
	"testing"
	"time"
)

func TestNewConfig(t *testing.T) {
	t.Run("returns config with default values", func(t *testing.T) {
		cfg := NewConfig()

		if cfg == nil {
			t.Fatal("expected non-nil config")
		}

		if cfg.NodeID != 1 {
			t.Errorf("expected NodeID=1, got %d", cfg.NodeID)
		}

		if cfg.ListenAddress != "0.0.0.0:7000" {
			t.Errorf("expected ListenAddress=0.0.0.0:7000, got %s", cfg.ListenAddress)
		}

		if cfg.AdvertiseAddress != "" {
			t.Errorf("expected empty AdvertiseAddress, got %s", cfg.AdvertiseAddress)
		}

		if cfg.JoinAddresses != nil {
			t.Errorf("expected nil JoinAddresses, got %v", cfg.JoinAddresses)
		}

		if cfg.DataDir != "./data/cluster" {
			t.Errorf("expected DataDir=./data/cluster, got %s", cfg.DataDir)
		}

		if cfg.HeartbeatInterval != DefaultHeartbeatInterval {
			t.Errorf("expected HeartbeatInterval=%v, got %v", DefaultHeartbeatInterval, cfg.HeartbeatInterval)
		}

		if cfg.ElectionTimeout != DefaultElectionTimeout {
			t.Errorf("expected ElectionTimeout=%v, got %v", DefaultElectionTimeout, cfg.ElectionTimeout)
		}

		if cfg.SnapshotInterval != DefaultSnapshotInterval {
			t.Errorf("expected SnapshotInterval=%v, got %v", DefaultSnapshotInterval, cfg.SnapshotInterval)
		}

		if cfg.SnapshotThreshold != DefaultSnapshotThreshold {
			t.Errorf("expected SnapshotThreshold=%d, got %d", DefaultSnapshotThreshold, cfg.SnapshotThreshold)
		}

		if cfg.MaxConcurrentStreams != DefaultMaxConcurrentStreams {
			t.Errorf("expected MaxConcurrentStreams=%d, got %d", DefaultMaxConcurrentStreams, cfg.MaxConcurrentStreams)
		}
	})

	t.Run("default config passes validation", func(t *testing.T) {
		cfg := NewConfig()
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected default config to be valid, got error: %v", err)
		}
	})
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		modifyFunc  func(*Config)
		wantErr     bool
		errField    string
		errContains string
	}{
		{
			name:       "valid config passes",
			modifyFunc: nil,
			wantErr:    false,
		},
		{
			name: "zero NodeID fails",
			modifyFunc: func(c *Config) {
				c.NodeID = 0
			},
			wantErr:     true,
			errField:    "NodeID",
			errContains: "greater than 0",
		},
		{
			name: "empty ListenAddress fails",
			modifyFunc: func(c *Config) {
				c.ListenAddress = ""
			},
			wantErr:     true,
			errField:    "ListenAddress",
			errContains: "is required",
		},
		{
			name: "empty DataDir fails",
			modifyFunc: func(c *Config) {
				c.DataDir = ""
			},
			wantErr:     true,
			errField:    "DataDir",
			errContains: "is required",
		},
		{
			name: "zero HeartbeatInterval fails",
			modifyFunc: func(c *Config) {
				c.HeartbeatInterval = 0
			},
			wantErr:     true,
			errField:    "HeartbeatInterval",
			errContains: "must be positive",
		},
		{
			name: "negative HeartbeatInterval fails",
			modifyFunc: func(c *Config) {
				c.HeartbeatInterval = -1 * time.Second
			},
			wantErr:     true,
			errField:    "HeartbeatInterval",
			errContains: "must be positive",
		},
		{
			name: "zero ElectionTimeout fails",
			modifyFunc: func(c *Config) {
				c.ElectionTimeout = 0
			},
			wantErr:     true,
			errField:    "ElectionTimeout",
			errContains: "must be positive",
		},
		{
			name: "negative ElectionTimeout fails",
			modifyFunc: func(c *Config) {
				c.ElectionTimeout = -1 * time.Second
			},
			wantErr:     true,
			errField:    "ElectionTimeout",
			errContains: "must be positive",
		},
		{
			name: "ElectionTimeout less than 2x HeartbeatInterval fails",
			modifyFunc: func(c *Config) {
				c.HeartbeatInterval = 100 * time.Millisecond
				c.ElectionTimeout = 150 * time.Millisecond
			},
			wantErr:     true,
			errField:    "ElectionTimeout",
			errContains: "at least 2x HeartbeatInterval",
		},
		{
			name: "ElectionTimeout equal to 2x HeartbeatInterval passes",
			modifyFunc: func(c *Config) {
				c.HeartbeatInterval = 100 * time.Millisecond
				c.ElectionTimeout = 200 * time.Millisecond
			},
			wantErr: false,
		},
		{
			name: "zero SnapshotInterval fails",
			modifyFunc: func(c *Config) {
				c.SnapshotInterval = 0
			},
			wantErr:     true,
			errField:    "SnapshotInterval",
			errContains: "must be positive",
		},
		{
			name: "zero SnapshotThreshold fails",
			modifyFunc: func(c *Config) {
				c.SnapshotThreshold = 0
			},
			wantErr:     true,
			errField:    "SnapshotThreshold",
			errContains: "greater than 0",
		},
		{
			name: "zero MaxConcurrentStreams fails",
			modifyFunc: func(c *Config) {
				c.MaxConcurrentStreams = 0
			},
			wantErr:     true,
			errField:    "MaxConcurrentStreams",
			errContains: "must be positive",
		},
		{
			name: "negative MaxConcurrentStreams fails",
			modifyFunc: func(c *Config) {
				c.MaxConcurrentStreams = -1
			},
			wantErr:     true,
			errField:    "MaxConcurrentStreams",
			errContains: "must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			if tt.modifyFunc != nil {
				tt.modifyFunc(cfg)
			}

			err := cfg.Validate()

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				invalidErr, ok := err.(ErrInvalidConfig)
				if !ok {
					t.Fatalf("expected ErrInvalidConfig, got %T", err)
				}
				if tt.errField != "" && invalidErr.Field != tt.errField {
					t.Errorf("expected error field %q, got %q", tt.errField, invalidErr.Field)
				}
			} else if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestConfig_Clone(t *testing.T) {
	t.Run("clones all fields", func(t *testing.T) {
		original := &Config{
			NodeID:               42,
			ListenAddress:        "127.0.0.1:7000",
			AdvertiseAddress:     "192.168.1.10:7000",
			JoinAddresses:        []string{"192.168.1.1:7000", "192.168.1.2:7000"},
			DataDir:              "/var/lib/cluster",
			HeartbeatInterval:    200 * time.Millisecond,
			ElectionTimeout:      2 * time.Second,
			SnapshotInterval:     10 * time.Minute,
			SnapshotThreshold:    20000,
			MaxConcurrentStreams: 512,
		}

		clone := original.Clone()

		if clone == original {
			t.Error("clone should be a different pointer")
		}

		if clone.NodeID != original.NodeID {
			t.Errorf("NodeID mismatch: got %d, want %d", clone.NodeID, original.NodeID)
		}

		if clone.ListenAddress != original.ListenAddress {
			t.Errorf("ListenAddress mismatch: got %s, want %s", clone.ListenAddress, original.ListenAddress)
		}

		if clone.AdvertiseAddress != original.AdvertiseAddress {
			t.Errorf("AdvertiseAddress mismatch: got %s, want %s", clone.AdvertiseAddress, original.AdvertiseAddress)
		}

		if clone.DataDir != original.DataDir {
			t.Errorf("DataDir mismatch: got %s, want %s", clone.DataDir, original.DataDir)
		}

		if clone.HeartbeatInterval != original.HeartbeatInterval {
			t.Errorf("HeartbeatInterval mismatch: got %v, want %v", clone.HeartbeatInterval, original.HeartbeatInterval)
		}

		if clone.ElectionTimeout != original.ElectionTimeout {
			t.Errorf("ElectionTimeout mismatch: got %v, want %v", clone.ElectionTimeout, original.ElectionTimeout)
		}

		if clone.SnapshotInterval != original.SnapshotInterval {
			t.Errorf("SnapshotInterval mismatch: got %v, want %v", clone.SnapshotInterval, original.SnapshotInterval)
		}

		if clone.SnapshotThreshold != original.SnapshotThreshold {
			t.Errorf("SnapshotThreshold mismatch: got %d, want %d", clone.SnapshotThreshold, original.SnapshotThreshold)
		}

		if clone.MaxConcurrentStreams != original.MaxConcurrentStreams {
			t.Errorf("MaxConcurrentStreams mismatch: got %d, want %d", clone.MaxConcurrentStreams, original.MaxConcurrentStreams)
		}
	})

	t.Run("deep copies JoinAddresses", func(t *testing.T) {
		original := &Config{
			NodeID:        1,
			ListenAddress: "0.0.0.0:7000",
			JoinAddresses: []string{"addr1", "addr2"},
			DataDir:       "./data",
		}

		clone := original.Clone()

		// Modify original
		original.JoinAddresses[0] = "modified"

		// Clone should not be affected
		if clone.JoinAddresses[0] == "modified" {
			t.Error("modifying original JoinAddresses affected clone")
		}
	})

	t.Run("handles nil JoinAddresses", func(t *testing.T) {
		original := &Config{
			NodeID:        1,
			ListenAddress: "0.0.0.0:7000",
			JoinAddresses: nil,
			DataDir:       "./data",
		}

		clone := original.Clone()

		if clone.JoinAddresses != nil {
			t.Errorf("expected nil JoinAddresses, got %v", clone.JoinAddresses)
		}
	})

	t.Run("handles nil config", func(t *testing.T) {
		var cfg *Config
		clone := cfg.Clone()

		if clone != nil {
			t.Errorf("expected nil, got %v", clone)
		}
	})
}

func TestConfig_WithNodeID(t *testing.T) {
	original := NewConfig()
	modified := original.WithNodeID(42)

	if modified.NodeID != 42 {
		t.Errorf("expected NodeID=42, got %d", modified.NodeID)
	}

	if original.NodeID == 42 {
		t.Error("original should not be modified")
	}

	if modified == original {
		t.Error("should return a new config")
	}
}

func TestConfig_WithListenAddress(t *testing.T) {
	original := NewConfig()
	modified := original.WithListenAddress("127.0.0.1:8000")

	if modified.ListenAddress != "127.0.0.1:8000" {
		t.Errorf("expected ListenAddress=127.0.0.1:8000, got %s", modified.ListenAddress)
	}

	if original.ListenAddress == "127.0.0.1:8000" {
		t.Error("original should not be modified")
	}
}

func TestConfig_WithAdvertiseAddress(t *testing.T) {
	original := NewConfig()
	modified := original.WithAdvertiseAddress("192.168.1.10:7000")

	if modified.AdvertiseAddress != "192.168.1.10:7000" {
		t.Errorf("expected AdvertiseAddress=192.168.1.10:7000, got %s", modified.AdvertiseAddress)
	}

	if original.AdvertiseAddress == "192.168.1.10:7000" {
		t.Error("original should not be modified")
	}
}

func TestConfig_WithJoinAddresses(t *testing.T) {
	t.Run("sets join addresses", func(t *testing.T) {
		original := NewConfig()
		addresses := []string{"addr1", "addr2"}
		modified := original.WithJoinAddresses(addresses)

		if len(modified.JoinAddresses) != 2 {
			t.Errorf("expected 2 join addresses, got %d", len(modified.JoinAddresses))
		}

		if modified.JoinAddresses[0] != "addr1" || modified.JoinAddresses[1] != "addr2" {
			t.Errorf("unexpected join addresses: %v", modified.JoinAddresses)
		}

		// Verify deep copy
		addresses[0] = "modified"
		if modified.JoinAddresses[0] == "modified" {
			t.Error("JoinAddresses should be a deep copy")
		}
	})

	t.Run("handles nil addresses", func(t *testing.T) {
		original := NewConfig().WithJoinAddresses([]string{"addr1"})
		modified := original.WithJoinAddresses(nil)

		if modified.JoinAddresses != nil {
			t.Errorf("expected nil JoinAddresses, got %v", modified.JoinAddresses)
		}
	})
}

func TestConfig_WithDataDir(t *testing.T) {
	original := NewConfig()
	modified := original.WithDataDir("/var/lib/cluster")

	if modified.DataDir != "/var/lib/cluster" {
		t.Errorf("expected DataDir=/var/lib/cluster, got %s", modified.DataDir)
	}

	if original.DataDir == "/var/lib/cluster" {
		t.Error("original should not be modified")
	}
}

func TestConfig_WithHeartbeatInterval(t *testing.T) {
	original := NewConfig()
	modified := original.WithHeartbeatInterval(200 * time.Millisecond)

	if modified.HeartbeatInterval != 200*time.Millisecond {
		t.Errorf("expected HeartbeatInterval=200ms, got %v", modified.HeartbeatInterval)
	}

	if original.HeartbeatInterval == 200*time.Millisecond {
		t.Error("original should not be modified")
	}
}

func TestConfig_WithElectionTimeout(t *testing.T) {
	original := NewConfig()
	modified := original.WithElectionTimeout(5 * time.Second)

	if modified.ElectionTimeout != 5*time.Second {
		t.Errorf("expected ElectionTimeout=5s, got %v", modified.ElectionTimeout)
	}

	if original.ElectionTimeout == 5*time.Second {
		t.Error("original should not be modified")
	}
}

func TestConfig_WithSnapshotInterval(t *testing.T) {
	original := NewConfig()
	modified := original.WithSnapshotInterval(10 * time.Minute)

	if modified.SnapshotInterval != 10*time.Minute {
		t.Errorf("expected SnapshotInterval=10m, got %v", modified.SnapshotInterval)
	}

	if original.SnapshotInterval == 10*time.Minute {
		t.Error("original should not be modified")
	}
}

func TestConfig_WithSnapshotThreshold(t *testing.T) {
	original := NewConfig()
	modified := original.WithSnapshotThreshold(50000)

	if modified.SnapshotThreshold != 50000 {
		t.Errorf("expected SnapshotThreshold=50000, got %d", modified.SnapshotThreshold)
	}

	if original.SnapshotThreshold == 50000 {
		t.Error("original should not be modified")
	}
}

func TestConfig_WithMaxConcurrentStreams(t *testing.T) {
	original := NewConfig()
	modified := original.WithMaxConcurrentStreams(512)

	if modified.MaxConcurrentStreams != 512 {
		t.Errorf("expected MaxConcurrentStreams=512, got %d", modified.MaxConcurrentStreams)
	}

	if original.MaxConcurrentStreams == 512 {
		t.Error("original should not be modified")
	}
}

func TestConfig_GetAdvertiseAddress(t *testing.T) {
	tests := []struct {
		name             string
		listenAddress    string
		advertiseAddress string
		want             string
	}{
		{
			name:             "returns AdvertiseAddress when set",
			listenAddress:    "0.0.0.0:7000",
			advertiseAddress: "192.168.1.10:7000",
			want:             "192.168.1.10:7000",
		},
		{
			name:             "falls back to ListenAddress when AdvertiseAddress is empty",
			listenAddress:    "0.0.0.0:7000",
			advertiseAddress: "",
			want:             "0.0.0.0:7000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ListenAddress:    tt.listenAddress,
				AdvertiseAddress: tt.advertiseAddress,
			}

			got := cfg.GetAdvertiseAddress()
			if got != tt.want {
				t.Errorf("GetAdvertiseAddress() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConfig_IsBootstrap(t *testing.T) {
	tests := []struct {
		name          string
		joinAddresses []string
		want          bool
	}{
		{
			name:          "returns true when JoinAddresses is nil",
			joinAddresses: nil,
			want:          true,
		},
		{
			name:          "returns true when JoinAddresses is empty",
			joinAddresses: []string{},
			want:          true,
		},
		{
			name:          "returns false when JoinAddresses has one element",
			joinAddresses: []string{"192.168.1.1:7000"},
			want:          false,
		},
		{
			name:          "returns false when JoinAddresses has multiple elements",
			joinAddresses: []string{"192.168.1.1:7000", "192.168.1.2:7000"},
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				JoinAddresses: tt.joinAddresses,
			}

			got := cfg.IsBootstrap()
			if got != tt.want {
				t.Errorf("IsBootstrap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_BuilderChaining(t *testing.T) {
	cfg := NewConfig().
		WithNodeID(42).
		WithListenAddress("127.0.0.1:8000").
		WithAdvertiseAddress("192.168.1.10:8000").
		WithJoinAddresses([]string{"seed1:7000", "seed2:7000"}).
		WithDataDir("/custom/data").
		WithHeartbeatInterval(50 * time.Millisecond).
		WithElectionTimeout(500 * time.Millisecond).
		WithSnapshotInterval(1 * time.Minute).
		WithSnapshotThreshold(5000).
		WithMaxConcurrentStreams(128)

	if cfg.NodeID != 42 {
		t.Errorf("NodeID = %d, want 42", cfg.NodeID)
	}
	if cfg.ListenAddress != "127.0.0.1:8000" {
		t.Errorf("ListenAddress = %s, want 127.0.0.1:8000", cfg.ListenAddress)
	}
	if cfg.AdvertiseAddress != "192.168.1.10:8000" {
		t.Errorf("AdvertiseAddress = %s, want 192.168.1.10:8000", cfg.AdvertiseAddress)
	}
	if len(cfg.JoinAddresses) != 2 {
		t.Errorf("len(JoinAddresses) = %d, want 2", len(cfg.JoinAddresses))
	}
	if cfg.DataDir != "/custom/data" {
		t.Errorf("DataDir = %s, want /custom/data", cfg.DataDir)
	}
	if cfg.HeartbeatInterval != 50*time.Millisecond {
		t.Errorf("HeartbeatInterval = %v, want 50ms", cfg.HeartbeatInterval)
	}
	if cfg.ElectionTimeout != 500*time.Millisecond {
		t.Errorf("ElectionTimeout = %v, want 500ms", cfg.ElectionTimeout)
	}
	if cfg.SnapshotInterval != 1*time.Minute {
		t.Errorf("SnapshotInterval = %v, want 1m", cfg.SnapshotInterval)
	}
	if cfg.SnapshotThreshold != 5000 {
		t.Errorf("SnapshotThreshold = %d, want 5000", cfg.SnapshotThreshold)
	}
	if cfg.MaxConcurrentStreams != 128 {
		t.Errorf("MaxConcurrentStreams = %d, want 128", cfg.MaxConcurrentStreams)
	}
}
