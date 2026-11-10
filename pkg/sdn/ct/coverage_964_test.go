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

package ct

import (
	"context"
	"strconv"
	"testing"
)

func TestNextZone(t *testing.T) {
	tests := []struct {
		name string
		zone uint16
		want uint16
	}{
		{name: "advances by one", zone: 41, want: 42},
		{name: "advances from the lowest zone", zone: MinZone, want: MinZone + 1},
		{name: "wraps past the highest zone and skips reserved zone 0", zone: MaxZone, want: MinZone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nextZone(tt.zone); got != tt.want {
				t.Fatalf("nextZone(%d) = %d, want %d", tt.zone, got, tt.want)
			}
		})
	}
}

// keyHashingToMaxZone finds a key whose "owner/key" allocation name hashes
// onto MaxZone, so a collision there forces the probe to wrap around.
func keyHashingToMaxZone(t *testing.T, owner string) string {
	t.Helper()
	for i := 0; i < 4*zoneSpace*16; i++ {
		key := "k" + strconv.Itoa(i)
		if hashZone(name(owner, key)) == MaxZone {
			return key
		}
	}
	t.Fatal("no key hashing to MaxZone found")
	return ""
}

func TestZoneAllocator_CollisionProbeWrapsToMinZone(t *testing.T) {
	const owner = "firewall"
	key := keyHashingToMaxZone(t, owner)

	// The key hashes onto MaxZone, which is taken, so the probe must wrap
	// around, skip reserved zone 0 and take the first free low zone.
	tests := []struct {
		name  string
		taken map[string]uint16
		want  uint16
	}{
		{
			name:  "wraps to MinZone",
			taken: map[string]uint16{"nat/high": MaxZone},
			want:  MinZone,
		},
		{
			name:  "wraps and keeps probing past a taken MinZone",
			taken: map[string]uint16{"nat/high": MaxZone, "nat/low": MinZone},
			want:  MinZone + 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			persister := &memPersister{saved: tt.taken}
			alloc := NewZoneAllocator(persister)
			if err := alloc.Restore(ctx); err != nil {
				t.Fatalf("Restore: %v", err)
			}

			zone, err := alloc.Allocate(ctx, owner, key)
			if err != nil {
				t.Fatalf("Allocate: %v", err)
			}
			if zone != tt.want {
				t.Fatalf("Allocate = %d, want %d after wrap-around probe", zone, tt.want)
			}
			if got := persister.saved[name(owner, key)]; got != tt.want {
				t.Fatalf("persisted zone = %d, want %d", got, tt.want)
			}
		})
	}
}
