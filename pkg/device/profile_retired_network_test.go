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

package device

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// TestValidateNetworkPhases_RetiredTrusted refuses every way a profile can
// still name the retired "trusted" network, and accepts an admitted one.
func TestValidateNetworkPhases_RetiredTrusted(t *testing.T) {
	cases := map[string]*entities.DeviceProfile{
		`networks["trusted"]`:     {Networks: map[string]*entities.NetworkPhaseConfig{"trusted": {VLAN: 406}}},
		"post_enrollment_network": {PostEnrollmentNetwork: "trusted"},
		"enrollment_network":      {EnrollmentNetwork: "trusted"},
		"failure_network":         {FailureNetwork: "trusted"},
		"zone":                    {Zone: "trusted"},
		`networks["admitted"].zone`: {Networks: map[string]*entities.NetworkPhaseConfig{
			"admitted": {VLAN: 406, Zone: "trusted"},
		}},
	}
	for field, profile := range cases {
		err := validateNetworkPhases(profile)
		var target ErrRetiredNetworkKey
		if !errors.As(err, &target) || target.Field != field {
			t.Fatalf("%s: want ErrRetiredNetworkKey{%s}, got %v", field, field, err)
		}
		if !strings.Contains(err.Error(), "admitted") {
			t.Errorf("%s: message %q should name the replacement", field, err.Error())
		}
	}

	ok := &entities.DeviceProfile{Networks: map[string]*entities.NetworkPhaseConfig{
		"provisioning": {VLAN: 405, Zone: "provisioning"},
		"admitted":     {VLAN: 406, Zone: "control-plane"},
	}}
	if err := validateNetworkPhases(ok); err != nil {
		t.Fatalf("an admitted profile must validate: %v", err)
	}
}
