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

package bgp

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"
)

// mockSpeaker implements SpeakerInterface for testing.
type transitMockSpeaker struct {
	started           bool
	routerID          netip.Addr
	asn               uint32
	announceErr       error
	withdrawErr       error
	announcedPrefixes []netip.Prefix
	withdrawnPrefixes []netip.Prefix
	withdrawCallCount int
}

func newTransitMockSpeaker() *transitMockSpeaker {
	return &transitMockSpeaker{
		started:           true,
		routerID:          netip.MustParseAddr("10.0.0.1"),
		asn:               65000,
		announcedPrefixes: make([]netip.Prefix, 0),
		withdrawnPrefixes: make([]netip.Prefix, 0),
	}
}

func (m *transitMockSpeaker) AnnouncePrefix(ctx context.Context, prefix netip.Prefix, nextHop netip.Addr, attrs *PathAttributes) error {
	if m.announceErr != nil {
		return m.announceErr
	}
	m.announcedPrefixes = append(m.announcedPrefixes, prefix)
	return nil
}

func (m *transitMockSpeaker) WithdrawPrefix(ctx context.Context, prefix netip.Prefix) error {
	m.withdrawCallCount++
	if m.withdrawErr != nil {
		return m.withdrawErr
	}
	m.withdrawnPrefixes = append(m.withdrawnPrefixes, prefix)
	return nil
}

func (m *transitMockSpeaker) IsStarted() bool {
	return m.started
}

func (m *transitMockSpeaker) GetRouterID() string {
	return m.routerID.String()
}

func (m *transitMockSpeaker) GetASN() uint32 {
	return m.asn
}

func transitTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestNewTransitManager tests transit manager creation.
func TestNewTransitManager(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		speaker     SpeakerInterface
		tier        SpeakerTier
		logger      *slog.Logger
		opts        []TransitManagerOption
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid creation with backbone tier",
			speaker: newTransitMockSpeaker(),
			tier:    SpeakerTierBackbone,
			logger:  transitTestLogger(),
			wantErr: false,
		},
		{
			name:    "valid creation with datacenter tier",
			speaker: newTransitMockSpeaker(),
			tier:    SpeakerTierDatacenter,
			logger:  transitTestLogger(),
			wantErr: false,
		},
		{
			name:    "valid creation with coordinator tier",
			speaker: newTransitMockSpeaker(),
			tier:    SpeakerTierCoordinator,
			logger:  transitTestLogger(),
			wantErr: false,
		},
		{
			name:    "valid creation with options",
			speaker: newTransitMockSpeaker(),
			tier:    SpeakerTierBackbone,
			logger:  transitTestLogger(),
			opts: []TransitManagerOption{
				WithDefaultLocalPref(200),
				WithDefaultMED(50),
			},
			wantErr: false,
		},
		{
			name:        "nil speaker",
			speaker:     nil,
			tier:        SpeakerTierBackbone,
			logger:      transitTestLogger(),
			wantErr:     true,
			errContains: "speaker is nil",
		},
		{
			name:        "nil logger",
			speaker:     newTransitMockSpeaker(),
			tier:        SpeakerTierBackbone,
			logger:      nil,
			wantErr:     true,
			errContains: "logger is nil",
		},
		{
			name:        "unknown tier",
			speaker:     newTransitMockSpeaker(),
			tier:        SpeakerTierUnknown,
			logger:      transitTestLogger(),
			wantErr:     true,
			errContains: "invalid speaker tier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tm, err := NewTransitManager(tt.speaker, tt.tier, tt.logger, tt.opts...)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errContains != "" && !containsString(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tm == nil {
				t.Fatal("expected transit manager, got nil")
			}

			if tm.GetTier() != tt.tier {
				t.Errorf("tier = %v, want %v", tm.GetTier(), tt.tier)
			}
		})
	}
}

// TestTransitManagerStartStop tests start and stop operations.
func TestTransitManagerStartStop(t *testing.T) {
	t.Parallel()

	t.Run("start success", func(t *testing.T) {
		t.Parallel()

		speaker := newTransitMockSpeaker()
		tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := tm.Start(ctx); err != nil {
			t.Errorf("Start() error = %v", err)
		}

		if !tm.IsStarted() {
			t.Error("expected IsStarted() = true")
		}
	})

	t.Run("start when already started", func(t *testing.T) {
		t.Parallel()

		speaker := newTransitMockSpeaker()
		tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := tm.Start(ctx); err != nil {
			t.Fatalf("first Start() error = %v", err)
		}

		err = tm.Start(ctx)
		if err == nil {
			t.Error("expected error on second Start()")
		}
	})

	t.Run("start with speaker not started", func(t *testing.T) {
		t.Parallel()

		speaker := newTransitMockSpeaker()
		speaker.started = false
		tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		err = tm.Start(ctx)
		if err == nil {
			t.Error("expected error when speaker not started")
		}
	})

	t.Run("stop success", func(t *testing.T) {
		t.Parallel()

		speaker := newTransitMockSpeaker()
		tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := tm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		if err := tm.Stop(ctx); err != nil {
			t.Errorf("Stop() error = %v", err)
		}

		if tm.IsStarted() {
			t.Error("expected IsStarted() = false after stop")
		}
	})

	t.Run("stop when not started", func(t *testing.T) {
		t.Parallel()

		speaker := newTransitMockSpeaker()
		tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := tm.Stop(ctx); err != nil {
			t.Errorf("Stop() when not started should not error: %v", err)
		}
	})
}

// TestAnnounceIPv6Prefix tests IPv6 prefix announcement.
func TestAnnounceIPv6Prefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		prefix      netip.Prefix
		opts        []AnnounceOption
		setupFn     func(*transitMockSpeaker)
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid IPv6 prefix",
			prefix:  netip.MustParsePrefix("2001:DB8::/36"),
			wantErr: false,
		},
		{
			name:   "valid IPv6 prefix with options",
			prefix: netip.MustParsePrefix("2001:DB8::/48"),
			opts: []AnnounceOption{
				WithNextHop(netip.MustParseAddr("2001:DB8::1")),
				WithLocalPref(200),
				WithMED(50),
				WithASPathPrepend(2),
				WithCommunities("65000:100", "65000:200"),
			},
			wantErr: false,
		},
		{
			name:        "invalid prefix",
			prefix:      netip.Prefix{},
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:        "IPv4 prefix instead of IPv6",
			prefix:      netip.MustParsePrefix("203.0.113.0/24"),
			wantErr:     true,
			errContains: "IPv6",
		},
		{
			name:   "speaker announce error",
			prefix: netip.MustParsePrefix("2001:DB8::/36"),
			setupFn: func(m *transitMockSpeaker) {
				m.announceErr = errors.New("mock announce error")
			},
			wantErr:     true,
			errContains: "announce",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			speaker := newTransitMockSpeaker()
			if tt.setupFn != nil {
				tt.setupFn(speaker)
			}

			tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
			if err != nil {
				t.Fatalf("failed to create manager: %v", err)
			}

			ctx := context.Background()
			if err := tm.Start(ctx); err != nil {
				t.Fatalf("Start() error = %v", err)
			}

			err = tm.AnnounceIPv6Prefix(ctx, tt.prefix, tt.opts...)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errContains != "" && !containsString(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestAnnounceIPv4Prefix tests IPv4 prefix announcement.
func TestAnnounceIPv4Prefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		prefix      netip.Prefix
		opts        []AnnounceOption
		setupFn     func(*transitMockSpeaker)
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid IPv4 prefix",
			prefix:  netip.MustParsePrefix("203.0.113.0/24"),
			wantErr: false,
		},
		{
			name:   "valid IPv4 prefix with options",
			prefix: netip.MustParsePrefix("203.0.113.0/24"),
			opts: []AnnounceOption{
				WithNextHop(netip.MustParseAddr("203.0.113.1")),
				WithLocalPref(150),
				WithMED(100),
			},
			wantErr: false,
		},
		{
			name:        "invalid prefix",
			prefix:      netip.Prefix{},
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:        "IPv6 prefix instead of IPv4",
			prefix:      netip.MustParsePrefix("2001:DB8::/36"),
			wantErr:     true,
			errContains: "IPv4",
		},
		{
			name:   "speaker announce error",
			prefix: netip.MustParsePrefix("203.0.113.0/24"),
			setupFn: func(m *transitMockSpeaker) {
				m.announceErr = errors.New("mock announce error")
			},
			wantErr:     true,
			errContains: "announce",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			speaker := newTransitMockSpeaker()
			if tt.setupFn != nil {
				tt.setupFn(speaker)
			}

			tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
			if err != nil {
				t.Fatalf("failed to create manager: %v", err)
			}

			ctx := context.Background()
			if err := tm.Start(ctx); err != nil {
				t.Fatalf("Start() error = %v", err)
			}

			err = tm.AnnounceIPv4Prefix(ctx, tt.prefix, tt.opts...)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errContains != "" && !containsString(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestWithdrawPrefix tests prefix withdrawal.
func TestWithdrawPrefix(t *testing.T) {
	t.Parallel()

	t.Run("withdraw IPv6 prefix", func(t *testing.T) {
		t.Parallel()

		speaker := newTransitMockSpeaker()
		tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := tm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		prefix := netip.MustParsePrefix("2001:DB8::/36")
		if err := tm.AnnounceIPv6Prefix(ctx, prefix); err != nil {
			t.Fatalf("AnnounceIPv6Prefix() error = %v", err)
		}

		if err := tm.WithdrawPrefix(ctx, prefix); err != nil {
			t.Errorf("WithdrawPrefix() error = %v", err)
		}

		// Verify prefix is no longer in list
		prefixes := tm.ListAnnouncedPrefixes()
		for _, p := range prefixes {
			if p == prefix {
				t.Error("prefix should have been withdrawn")
			}
		}
	})

	t.Run("withdraw IPv4 prefix", func(t *testing.T) {
		t.Parallel()

		speaker := newTransitMockSpeaker()
		tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := tm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		prefix := netip.MustParsePrefix("203.0.113.0/24")
		if err := tm.AnnounceIPv4Prefix(ctx, prefix); err != nil {
			t.Fatalf("AnnounceIPv4Prefix() error = %v", err)
		}

		if err := tm.WithdrawPrefix(ctx, prefix); err != nil {
			t.Errorf("WithdrawPrefix() error = %v", err)
		}
		if !slices.Equal(speaker.withdrawnPrefixes, []netip.Prefix{prefix}) {
			t.Errorf("speaker withdrew %v, want [%v]", speaker.withdrawnPrefixes, prefix)
		}
	})

	t.Run("withdraw non-existent prefix", func(t *testing.T) {
		t.Parallel()

		speaker := newTransitMockSpeaker()
		tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := tm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		prefix := netip.MustParsePrefix("10.0.0.0/8")
		err = tm.WithdrawPrefix(ctx, prefix)
		if err == nil {
			t.Error("expected error for non-existent prefix")
		}
	})

	t.Run("withdraw invalid prefix", func(t *testing.T) {
		t.Parallel()

		speaker := newTransitMockSpeaker()
		tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := tm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		err = tm.WithdrawPrefix(ctx, netip.Prefix{})
		if err == nil {
			t.Error("expected error for invalid prefix")
		}
	})

	t.Run("withdraw with speaker error", func(t *testing.T) {
		t.Parallel()

		speaker := newTransitMockSpeaker()
		tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := tm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		prefix := netip.MustParsePrefix("203.0.113.0/24")
		if err := tm.AnnounceIPv4Prefix(ctx, prefix); err != nil {
			t.Fatalf("AnnounceIPv4Prefix() error = %v", err)
		}

		speaker.withdrawErr = errors.New("mock withdraw error")

		err = tm.WithdrawPrefix(ctx, prefix)
		if err == nil {
			t.Error("expected error on withdraw failure")
		}
	})
}

// TestListAnnouncedPrefixes tests listing announced prefixes.
func TestListAnnouncedPrefixes(t *testing.T) {
	t.Parallel()

	speaker := newTransitMockSpeaker()
	tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := tm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Initially empty
	prefixes := tm.ListAnnouncedPrefixes()
	if len(prefixes) != 0 {
		t.Errorf("expected 0 prefixes, got %d", len(prefixes))
	}

	// Add prefixes
	ipv6Prefix := netip.MustParsePrefix("2001:DB8::/36")
	ipv4Prefix := netip.MustParsePrefix("203.0.113.0/24")

	if err := tm.AnnounceIPv6Prefix(ctx, ipv6Prefix); err != nil {
		t.Fatalf("AnnounceIPv6Prefix() error = %v", err)
	}

	if err := tm.AnnounceIPv4Prefix(ctx, ipv4Prefix); err != nil {
		t.Fatalf("AnnounceIPv4Prefix() error = %v", err)
	}

	prefixes = tm.ListAnnouncedPrefixes()
	if len(prefixes) != 2 {
		t.Errorf("expected 2 prefixes, got %d", len(prefixes))
	}

	// Test IPv6-specific list
	ipv6List := tm.ListAnnouncedIPv6Prefixes()
	if len(ipv6List) != 1 {
		t.Errorf("expected 1 IPv6 prefix, got %d", len(ipv6List))
	}

	// Test IPv4-specific list
	ipv4List := tm.ListAnnouncedIPv4Prefixes()
	if len(ipv4List) != 1 {
		t.Errorf("expected 1 IPv4 prefix, got %d", len(ipv4List))
	}
}

// TestGetAnnouncedPrefix tests retrieving a specific announced prefix.
func TestGetAnnouncedPrefix(t *testing.T) {
	t.Parallel()

	speaker := newTransitMockSpeaker()
	tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := tm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	prefix := netip.MustParsePrefix("2001:DB8::/36")
	if err := tm.AnnounceIPv6Prefix(ctx, prefix, WithLocalPref(200)); err != nil {
		t.Fatalf("AnnounceIPv6Prefix() error = %v", err)
	}

	announced, err := tm.GetAnnouncedPrefix(prefix)
	if err != nil {
		t.Fatalf("GetAnnouncedPrefix() error = %v", err)
	}

	if announced.Prefix != prefix {
		t.Errorf("prefix = %v, want %v", announced.Prefix, prefix)
	}

	if announced.LocalPref != 200 {
		t.Errorf("local_pref = %d, want 200", announced.LocalPref)
	}

	// Test non-existent prefix
	_, err = tm.GetAnnouncedPrefix(netip.MustParsePrefix("10.0.0.0/8"))
	if err == nil {
		t.Error("expected error for non-existent prefix")
	}

	// Test invalid prefix
	_, err = tm.GetAnnouncedPrefix(netip.Prefix{})
	if err == nil {
		t.Error("expected error for invalid prefix")
	}
}

// TestDuplicateAnnouncement tests announcing the same prefix twice.
func TestDuplicateAnnouncement(t *testing.T) {
	t.Parallel()

	speaker := newTransitMockSpeaker()
	tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := tm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	prefix := netip.MustParsePrefix("2001:DB8::/36")
	if err := tm.AnnounceIPv6Prefix(ctx, prefix); err != nil {
		t.Fatalf("first AnnounceIPv6Prefix() error = %v", err)
	}

	err = tm.AnnounceIPv6Prefix(ctx, prefix)
	if err == nil {
		t.Error("expected error for duplicate announcement")
	}
	if !slices.Equal(speaker.announcedPrefixes, []netip.Prefix{prefix}) {
		t.Errorf("speaker announced %v, want only the first [%v]", speaker.announcedPrefixes, prefix)
	}
}

// TestPrefixAttributeUpdates tests updating prefix attributes.
func TestPrefixAttributeUpdates(t *testing.T) {
	t.Parallel()

	speaker := newTransitMockSpeaker()
	tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := tm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	prefix := netip.MustParsePrefix("2001:DB8::/36")
	if err := tm.AnnounceIPv6Prefix(ctx, prefix); err != nil {
		t.Fatalf("AnnounceIPv6Prefix() error = %v", err)
	}

	t.Run("SetASPathPrepend", func(t *testing.T) {
		if err := tm.SetASPathPrepend(prefix, 3); err != nil {
			t.Errorf("SetASPathPrepend() error = %v", err)
		}

		announced, _ := tm.GetAnnouncedPrefix(prefix)
		if announced.ASPathPrepend != 3 {
			t.Errorf("ASPathPrepend = %d, want 3", announced.ASPathPrepend)
		}
	})

	t.Run("SetASPathPrepend invalid count", func(t *testing.T) {
		err := tm.SetASPathPrepend(prefix, -1)
		if err == nil {
			t.Error("expected error for negative prepend count")
		}
	})

	t.Run("SetCommunities", func(t *testing.T) {
		communities := []string{"65000:100", "65000:200"}
		if err := tm.SetCommunities(prefix, communities); err != nil {
			t.Errorf("SetCommunities() error = %v", err)
		}

		announced, _ := tm.GetAnnouncedPrefix(prefix)
		if len(announced.Communities) != 2 {
			t.Errorf("Communities len = %d, want 2", len(announced.Communities))
		}
	})

	t.Run("SetMED", func(t *testing.T) {
		if err := tm.SetMED(prefix, 100); err != nil {
			t.Errorf("SetMED() error = %v", err)
		}

		announced, _ := tm.GetAnnouncedPrefix(prefix)
		if announced.MED != 100 {
			t.Errorf("MED = %d, want 100", announced.MED)
		}
	})

	t.Run("SetLocalPref", func(t *testing.T) {
		if err := tm.SetLocalPref(prefix, 250); err != nil {
			t.Errorf("SetLocalPref() error = %v", err)
		}

		announced, _ := tm.GetAnnouncedPrefix(prefix)
		if announced.LocalPref != 250 {
			t.Errorf("LocalPref = %d, want 250", announced.LocalPref)
		}
	})
}

// TestPrefixCounts tests prefix counting methods.
func TestPrefixCounts(t *testing.T) {
	t.Parallel()

	speaker := newTransitMockSpeaker()
	tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := tm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Initially all counts should be 0
	if tm.PrefixCount() != 0 {
		t.Errorf("PrefixCount() = %d, want 0", tm.PrefixCount())
	}
	if tm.IPv4PrefixCount() != 0 {
		t.Errorf("IPv4PrefixCount() = %d, want 0", tm.IPv4PrefixCount())
	}
	if tm.IPv6PrefixCount() != 0 {
		t.Errorf("IPv6PrefixCount() = %d, want 0", tm.IPv6PrefixCount())
	}

	// Add some prefixes
	if err := tm.AnnounceIPv6Prefix(ctx, netip.MustParsePrefix("2001:DB8::/36")); err != nil {
		t.Fatalf("AnnounceIPv6Prefix() error = %v", err)
	}
	if err := tm.AnnounceIPv6Prefix(ctx, netip.MustParsePrefix("2001:DB8:1000::/48")); err != nil {
		t.Fatalf("AnnounceIPv6Prefix() error = %v", err)
	}
	if err := tm.AnnounceIPv4Prefix(ctx, netip.MustParsePrefix("203.0.113.0/24")); err != nil {
		t.Fatalf("AnnounceIPv4Prefix() error = %v", err)
	}

	if tm.PrefixCount() != 3 {
		t.Errorf("PrefixCount() = %d, want 3", tm.PrefixCount())
	}
	if tm.IPv4PrefixCount() != 1 {
		t.Errorf("IPv4PrefixCount() = %d, want 1", tm.IPv4PrefixCount())
	}
	if tm.IPv6PrefixCount() != 2 {
		t.Errorf("IPv6PrefixCount() = %d, want 2", tm.IPv6PrefixCount())
	}
}

// TestOperationsWithoutStart tests operations when manager is not started.
func TestOperationsWithoutStart(t *testing.T) {
	t.Parallel()

	speaker := newTransitMockSpeaker()
	tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	prefix := netip.MustParsePrefix("2001:DB8::/36")

	t.Run("AnnounceIPv6Prefix", func(t *testing.T) {
		err := tm.AnnounceIPv6Prefix(ctx, prefix)
		if err == nil {
			t.Error("expected error when not started")
		}
	})

	t.Run("AnnounceIPv4Prefix", func(t *testing.T) {
		err := tm.AnnounceIPv4Prefix(ctx, netip.MustParsePrefix("203.0.113.0/24"))
		if err == nil {
			t.Error("expected error when not started")
		}
	})

	t.Run("WithdrawPrefix", func(t *testing.T) {
		err := tm.WithdrawPrefix(ctx, prefix)
		if err == nil {
			t.Error("expected error when not started")
		}
	})

	t.Run("SetASPathPrepend", func(t *testing.T) {
		err := tm.SetASPathPrepend(prefix, 1)
		if err == nil {
			t.Error("expected error when not started")
		}
	})

	t.Run("SetCommunities", func(t *testing.T) {
		err := tm.SetCommunities(prefix, []string{"65000:100"})
		if err == nil {
			t.Error("expected error when not started")
		}
	})

	t.Run("SetMED", func(t *testing.T) {
		err := tm.SetMED(prefix, 100)
		if err == nil {
			t.Error("expected error when not started")
		}
	})

	t.Run("SetLocalPref", func(t *testing.T) {
		err := tm.SetLocalPref(prefix, 200)
		if err == nil {
			t.Error("expected error when not started")
		}
	})
}

// TestStopWithPrefixes tests stopping with active prefixes withdraws them.
func TestStopWithPrefixes(t *testing.T) {
	t.Parallel()

	speaker := newTransitMockSpeaker()
	tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := tm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Add some prefixes
	if err := tm.AnnounceIPv6Prefix(ctx, netip.MustParsePrefix("2001:DB8::/36")); err != nil {
		t.Fatalf("AnnounceIPv6Prefix() error = %v", err)
	}
	if err := tm.AnnounceIPv4Prefix(ctx, netip.MustParsePrefix("203.0.113.0/24")); err != nil {
		t.Fatalf("AnnounceIPv4Prefix() error = %v", err)
	}

	// Stop should withdraw all prefixes
	if err := tm.Stop(ctx); err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	if speaker.withdrawCallCount != 2 {
		t.Errorf("withdrawCallCount = %d, want 2", speaker.withdrawCallCount)
	}

	// Verify prefix counts are 0
	if tm.PrefixCount() != 0 {
		t.Errorf("PrefixCount() = %d, want 0 after stop", tm.PrefixCount())
	}
}

// TestStopWithWithdrawError tests Stop behavior when prefix withdrawal fails.
func TestStopWithWithdrawError(t *testing.T) {
	t.Parallel()

	speaker := newTransitMockSpeaker()
	tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := tm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Add IPv6 and IPv4 prefixes
	if err := tm.AnnounceIPv6Prefix(ctx, netip.MustParsePrefix("2001:DB8::/36")); err != nil {
		t.Fatalf("AnnounceIPv6Prefix() error = %v", err)
	}
	if err := tm.AnnounceIPv4Prefix(ctx, netip.MustParsePrefix("203.0.113.0/24")); err != nil {
		t.Fatalf("AnnounceIPv4Prefix() error = %v", err)
	}

	// Set withdraw error - Stop should still complete but return error
	speaker.withdrawErr = errors.New("mock withdraw error during stop")

	err = tm.Stop(ctx)
	if err == nil {
		t.Error("expected error when withdrawal fails during stop")
	}

	// Despite error, speaker should have attempted to withdraw both prefixes
	if speaker.withdrawCallCount != 2 {
		t.Errorf("withdrawCallCount = %d, want 2 (should attempt all withdrawals)", speaker.withdrawCallCount)
	}

	// Manager should still be marked as stopped
	if tm.IsStarted() {
		t.Error("expected IsStarted() = false even after withdrawal errors")
	}
}

// TestAnnouncedPrefixTimes tests timestamps on announced prefixes.
func TestAnnouncedPrefixTimes(t *testing.T) {
	t.Parallel()

	speaker := newTransitMockSpeaker()
	tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := tm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	before := time.Now()
	prefix := netip.MustParsePrefix("2001:DB8::/36")
	if err := tm.AnnounceIPv6Prefix(ctx, prefix); err != nil {
		t.Fatalf("AnnounceIPv6Prefix() error = %v", err)
	}
	after := time.Now()

	announced, err := tm.GetAnnouncedPrefix(prefix)
	if err != nil {
		t.Fatalf("GetAnnouncedPrefix() error = %v", err)
	}

	if announced.AnnouncedAt.Before(before) || announced.AnnouncedAt.After(after) {
		t.Error("AnnouncedAt not within expected time range")
	}

	if announced.UpdatedAt.Before(before) || announced.UpdatedAt.After(after) {
		t.Error("UpdatedAt not within expected time range")
	}

	// Update the prefix and verify UpdatedAt changes
	updateBefore := time.Now()
	if err := tm.SetMED(prefix, 100); err != nil {
		t.Fatalf("SetMED() error = %v", err)
	}
	updateAfter := time.Now()

	announced, err = tm.GetAnnouncedPrefix(prefix)
	if err != nil {
		t.Fatalf("GetAnnouncedPrefix() error = %v", err)
	}

	if announced.UpdatedAt.Before(updateBefore) || announced.UpdatedAt.After(updateAfter) {
		t.Error("UpdatedAt not updated after SetMED")
	}
}

// TestRouteOriginString tests RouteOrigin String method.
func TestRouteOriginString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		origin RouteOrigin
		want   string
	}{
		{RouteOriginIGP, "igp"},
		{RouteOriginEGP, "egp"},
		{RouteOriginIncomplete, "incomplete"},
		{RouteOrigin(255), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.origin.String(); got != tt.want {
				t.Errorf("RouteOrigin.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSpeakerTierStringTransit tests SpeakerTier String method.
func TestSpeakerTierStringTransit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		tier SpeakerTier
		want string
	}{
		{SpeakerTierBackbone, "backbone"},
		{SpeakerTierDatacenter, "datacenter"},
		{SpeakerTierCoordinator, "coordinator"},
		{SpeakerTierUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.tier.String(); got != tt.want {
				t.Errorf("SpeakerTier.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestWithASPathPrependNegative tests WithASPathPrepend with negative value.
func TestWithASPathPrependNegative(t *testing.T) {
	t.Parallel()

	cfg := &announceConfig{}
	opt := WithASPathPrepend(-5)
	opt(cfg)

	// Negative values should not change the default
	if cfg.asPathPrepend != 0 {
		t.Errorf("asPathPrepend = %d, want 0 for negative input", cfg.asPathPrepend)
	}
}

// TestSetASPathPrependPrefixNotFound tests SetASPathPrepend when prefix not found.
func TestSetASPathPrependPrefixNotFound(t *testing.T) {
	t.Parallel()

	speaker := newTransitMockSpeaker()
	tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := tm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Try to set AS path prepend on non-existent prefix
	err = tm.SetASPathPrepend(netip.MustParsePrefix("10.0.0.0/8"), 2)
	if err == nil {
		t.Error("expected error for non-existent prefix")
	}
}

// TestSetCommunitiesPrefixNotFound tests SetCommunities when prefix not found.
func TestSetCommunitiesPrefixNotFound(t *testing.T) {
	t.Parallel()

	speaker := newTransitMockSpeaker()
	tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := tm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Try to set communities on non-existent prefix
	err = tm.SetCommunities(netip.MustParsePrefix("10.0.0.0/8"), []string{"65000:100"})
	if err == nil {
		t.Error("expected error for non-existent prefix")
	}
}

// TestSetMEDPrefixNotFound tests SetMED when prefix not found.
func TestSetMEDPrefixNotFound(t *testing.T) {
	t.Parallel()

	speaker := newTransitMockSpeaker()
	tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := tm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Try to set MED on non-existent prefix
	err = tm.SetMED(netip.MustParsePrefix("10.0.0.0/8"), 100)
	if err == nil {
		t.Error("expected error for non-existent prefix")
	}
}

// TestSetLocalPrefPrefixNotFound tests SetLocalPref when prefix not found.
func TestSetLocalPrefPrefixNotFound(t *testing.T) {
	t.Parallel()

	speaker := newTransitMockSpeaker()
	tm, err := NewTransitManager(speaker, SpeakerTierBackbone, transitTestLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := tm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Try to set local preference on non-existent prefix
	err = tm.SetLocalPref(netip.MustParsePrefix("10.0.0.0/8"), 200)
	if err == nil {
		t.Error("expected error for non-existent prefix")
	}
}

// containsString checks if a string contains a substring.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
