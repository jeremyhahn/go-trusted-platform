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

package zone_test

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestErrorMessages verifies that each typed error produces a non-empty,
// descriptive message string containing the relevant field values.
func TestErrorMessages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		err     error
		contain []string
	}{
		{
			name:    "ErrDuplicateZone",
			err:     zone.ErrDuplicateZone{Name: "trusted"},
			contain: []string{"duplicate", "trusted"},
		},
		{
			name:    "ErrEmptyZoneName",
			err:     zone.ErrEmptyZoneName{},
			contain: []string{"empty"},
		},
		{
			name:    "ErrInvalidZoneName",
			err:     zone.ErrInvalidZoneName{Name: "BAD_NAME"},
			contain: []string{"BAD_NAME", "DNS-label"},
		},
		{
			name:    "ErrLifecycleRoleCount",
			err:     zone.ErrLifecycleRoleCount{Role: zone.LifecycleRoleProvisioning, Count: 2},
			contain: []string{"provisioning", "2"},
		},
		{
			name:    "ErrInvalidLifecycleRole",
			err:     zone.ErrInvalidLifecycleRole{Zone: "myz", Role: "bogus"},
			contain: []string{"myz", "bogus"},
		},
		{
			name:    "ErrUnknownZoneRef_isolate_from",
			err:     zone.ErrUnknownZoneRef{Source: "src", Field: "isolate_from", Target: "ghost"},
			contain: []string{"src", "isolate_from", "ghost"},
		},
		{
			name:    "ErrUnknownZoneRef_allow_to",
			err:     zone.ErrUnknownZoneRef{Source: "src", Field: "allow_to", Target: "phantom"},
			contain: []string{"src", "allow_to", "phantom"},
		},
		{
			name:    "ErrOOBWithInternetIngress",
			err:     zone.ErrOOBWithInternetIngress{Zone: "management"},
			contain: []string{"management", "oob", "internet_ingress"},
		},
		{
			name:    "ErrOmitLifecycleHolder",
			err:     zone.ErrOmitLifecycleHolder{Zone: zone.ZoneProvisioning, Role: zone.LifecycleRoleProvisioning},
			contain: []string{"provisioning"},
		},
		{
			name:    "ErrNoZoneForRole",
			err:     zone.ErrNoZoneForRole{Role: zone.LifecycleRoleQuarantine},
			contain: []string{"quarantine"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msg := tc.err.Error()
			if msg == "" {
				t.Errorf("%s.Error() returned empty string", tc.name)
			}
			for _, substr := range tc.contain {
				if !strings.Contains(msg, substr) {
					t.Errorf("%s.Error() = %q; want it to contain %q", tc.name, msg, substr)
				}
			}
		})
	}
}

// TestValidate_NameEndsWithHyphen verifies that a trailing hyphen is caught by
// the DNS-label safety check (exercises the trailing-hyphen branch of
// isDNSLabelSafe).
func TestValidate_NameEndsWithHyphen(t *testing.T) {
	t.Parallel()

	zones := zone.Defaults()
	zones = append(zones, zone.ZoneConfig{Name: "bad-"})
	err := zone.Validate(zones)
	var target zone.ErrInvalidZoneName
	if err == nil {
		t.Fatal("Validate: expected error for trailing-hyphen name, got nil")
	}
	if msg := err.Error(); !strings.Contains(msg, "bad-") {
		_ = target
		t.Errorf("error %q should mention the bad name", msg)
	}
}
