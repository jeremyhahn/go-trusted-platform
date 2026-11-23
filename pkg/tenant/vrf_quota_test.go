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

package tenant

import (
	"errors"
	"testing"
)

func TestVRFQuota_HasCapacity(t *testing.T) {
	quota := VRFQuota{
		MaxVRFs:      2,
		MaxNetworks:  10,
		MaxServices:  5,
		UsedVRFs:     1,
		UsedNetworks: 8,
		UsedServices: 5,
	}

	tests := []struct {
		name     string
		vrfs     int64
		networks int64
		services int64
		want     bool
	}{
		{name: "nothing requested", want: true},
		{name: "vrfs within limit", vrfs: 1, want: true},
		{name: "vrfs over limit", vrfs: 2, want: false},
		{name: "networks within limit", networks: 2, want: true},
		{name: "networks over limit", networks: 3, want: false},
		{name: "services over limit", services: 1, want: false},
		{name: "all within limits", vrfs: 1, networks: 2, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := quota.HasCapacity(tt.vrfs, tt.networks, tt.services); got != tt.want {
				t.Errorf("HasCapacity(%d, %d, %d) = %v, want %v", tt.vrfs, tt.networks, tt.services, got, tt.want)
			}
		})
	}
}

func TestVRFQuota_Reserve(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		quota := VRFQuota{MaxVRFs: 3, MaxNetworks: 10, MaxServices: 5}

		if err := quota.Reserve("acme", 1, 4, 2); err != nil {
			t.Fatalf("Reserve() error = %v", err)
		}
		if quota.UsedVRFs != 1 || quota.UsedNetworks != 4 || quota.UsedServices != 2 {
			t.Errorf("Used = (%d, %d, %d), want (1, 4, 2)", quota.UsedVRFs, quota.UsedNetworks, quota.UsedServices)
		}
	})

	tests := []struct {
		name     string
		vrfs     int64
		networks int64
		services int64
		want     ErrQuotaExceeded
	}{
		{
			name: "vrfs quota exceeded",
			vrfs: 2,
			want: ErrQuotaExceeded{TenantID: "acme", Resource: "VRFs", Requested: 2, Available: 1},
		},
		{
			name:     "networks quota exceeded",
			vrfs:     1,
			networks: 3,
			want:     ErrQuotaExceeded{TenantID: "acme", Resource: "networks", Requested: 3, Available: 2},
		},
		{
			name:     "services quota exceeded",
			vrfs:     1,
			networks: 1,
			services: 2,
			want:     ErrQuotaExceeded{TenantID: "acme", Resource: "services", Requested: 2, Available: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			quota := VRFQuota{
				MaxVRFs:      2,
				MaxNetworks:  10,
				MaxServices:  5,
				UsedVRFs:     1,
				UsedNetworks: 8,
				UsedServices: 4,
			}

			err := quota.Reserve("acme", tt.vrfs, tt.networks, tt.services)
			if err == nil {
				t.Fatal("Reserve() expected error")
			}

			var quotaErr ErrQuotaExceeded
			if !errors.As(err, &quotaErr) {
				t.Fatalf("Reserve() error type = %T, want ErrQuotaExceeded", err)
			}
			if quotaErr != tt.want {
				t.Errorf("Reserve() error = %+v, want %+v", quotaErr, tt.want)
			}
			if quota.UsedVRFs != 1 || quota.UsedNetworks != 8 || quota.UsedServices != 4 {
				t.Errorf("Used after refusal = (%d, %d, %d), want (1, 8, 4)",
					quota.UsedVRFs, quota.UsedNetworks, quota.UsedServices)
			}
		})
	}
}

func TestVRFQuota_Release(t *testing.T) {
	quota := VRFQuota{
		MaxVRFs:      5,
		MaxNetworks:  10,
		MaxServices:  5,
		UsedVRFs:     3,
		UsedNetworks: 6,
		UsedServices: 2,
	}

	quota.Release(1, 2, 1)
	if quota.UsedVRFs != 2 || quota.UsedNetworks != 4 || quota.UsedServices != 1 {
		t.Errorf("Used after Release = (%d, %d, %d), want (2, 4, 1)",
			quota.UsedVRFs, quota.UsedNetworks, quota.UsedServices)
	}

	quota.Release(10, 10, 10)
	if quota.UsedVRFs != 0 || quota.UsedNetworks != 0 || quota.UsedServices != 0 {
		t.Errorf("Used after over-release = (%d, %d, %d), want (0, 0, 0)",
			quota.UsedVRFs, quota.UsedNetworks, quota.UsedServices)
	}
}

func TestVRFQuota_SetLimits(t *testing.T) {
	quota := VRFQuota{
		MaxVRFs:      1,
		MaxNetworks:  2,
		MaxServices:  3,
		UsedVRFs:     1,
		UsedNetworks: 2,
		UsedServices: 3,
	}

	quota.SetLimits(VRFQuota{
		MaxVRFs:      4,
		MaxNetworks:  20,
		MaxServices:  8,
		UsedVRFs:     99,
		UsedNetworks: 99,
		UsedServices: 99,
	})

	if quota.MaxVRFs != 4 || quota.MaxNetworks != 20 || quota.MaxServices != 8 {
		t.Errorf("Max = (%d, %d, %d), want (4, 20, 8)", quota.MaxVRFs, quota.MaxNetworks, quota.MaxServices)
	}
	if quota.UsedVRFs != 1 || quota.UsedNetworks != 2 || quota.UsedServices != 3 {
		t.Errorf("Used = (%d, %d, %d), want (1, 2, 3)", quota.UsedVRFs, quota.UsedNetworks, quota.UsedServices)
	}
}

func TestVRFQuota_GetUtilization(t *testing.T) {
	quota := VRFQuota{
		MaxVRFs:      4,
		MaxNetworks:  10,
		MaxServices:  0,
		UsedVRFs:     1,
		UsedNetworks: 5,
		UsedServices: 3,
	}

	util := quota.GetUtilization()

	want := map[string]float64{"vrfs": 25, "networks": 50, "services": 0}
	if len(util) != len(want) {
		t.Errorf("GetUtilization() has %d keys, want %d: %v", len(util), len(want), util)
	}
	for key, w := range want {
		got, ok := util[key]
		if !ok {
			t.Errorf("GetUtilization() missing key %q", key)
			continue
		}
		if got != w {
			t.Errorf("GetUtilization()[%q] = %v, want %v", key, got, w)
		}
	}
}

func TestVRFQuota_Available(t *testing.T) {
	quota := VRFQuota{
		MaxVRFs:      4,
		MaxNetworks:  10,
		MaxServices:  2,
		UsedVRFs:     1,
		UsedNetworks: 10,
		UsedServices: 5,
	}

	if got := quota.AvailableVRFs(); got != 3 {
		t.Errorf("AvailableVRFs() = %d, want 3", got)
	}
	if got := quota.AvailableNetworks(); got != 0 {
		t.Errorf("AvailableNetworks() = %d, want 0", got)
	}
	if got := quota.AvailableServices(); got != 0 {
		t.Errorf("AvailableServices() = %d, want 0", got)
	}
}

func TestVRFQuota_NegativeCounts(t *testing.T) {
	newQuota := func() *VRFQuota {
		return &VRFQuota{
			MaxVRFs: 1, MaxNetworks: 2, MaxServices: 2,
			UsedVRFs: 1, UsedNetworks: 1, UsedServices: 1,
		}
	}
	check := func(t *testing.T, q *VRFQuota) {
		t.Helper()
		if q.UsedVRFs != 1 || q.UsedNetworks != 1 || q.UsedServices != 1 {
			t.Errorf("usage changed: vrfs=%d networks=%d services=%d", q.UsedVRFs, q.UsedNetworks, q.UsedServices)
		}
	}
	counts := [][3]int64{{-1, 0, 0}, {0, -1, 0}, {0, 0, -1}}
	for _, c := range counts {
		q := newQuota()
		err := q.Reserve("acme", c[0], c[1], c[2])
		var invalid ErrInvalidRequest
		if !errors.As(err, &invalid) {
			t.Errorf("Reserve(%v) = %v, want ErrInvalidRequest", c, err)
		}
		check(t, q)
		if q.HasCapacity(c[0], c[1], c[2]) {
			t.Errorf("HasCapacity(%v) = true, want false", c)
		}
	}
	q := newQuota()
	q.Release(-1, -1, -1)
	check(t, q)
}
