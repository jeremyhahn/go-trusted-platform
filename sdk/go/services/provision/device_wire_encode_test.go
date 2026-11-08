// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package provision

import (
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestDeviceRoleJSON(t *testing.T) {
	cases := map[platformv1.DeviceRole]string{
		platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED:   "",
		platformv1.DeviceRole_DEVICE_ROLE_EDGE:          "edge",
		platformv1.DeviceRole_DEVICE_ROLE_CONTROL_PLANE: "control-plane",
		platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER: "load-balancer",
	}
	for role, want := range cases {
		if got := DeviceRoleJSON(role); got != want {
			t.Errorf("DeviceRoleJSON(%v) = %q, want %q", role, got, want)
		}
	}
}

func TestEncodeTemplateJSON(t *testing.T) {
	rules := &platformv1.ProfileMatchRules{MacPrefix: "00:25:90"}
	out, err := EncodeTemplateJSON(&platformv1.DeviceTemplate{
		Name:       "edge",
		Role:       platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER,
		Config:     []byte("hostname: edge-01\n"),
		MatchRules: rules,
	})
	if err != nil {
		t.Fatalf("EncodeTemplateJSON: %v", err)
	}
	if out["name"] != "edge" || out["role"] != "load-balancer" || out["match_rules"] != rules {
		t.Errorf("out = %v, fields not mapped", out)
	}
	for _, absent := range []string{"tenant_id", "description", "config"} {
		if _, ok := out[absent]; ok {
			t.Errorf("%s present, want it left to the caller or omitted when unset", absent)
		}
	}
}

func TestEncodeTemplateJSON_RefusesBMC(t *testing.T) {
	_, err := EncodeTemplateJSON(&platformv1.DeviceTemplate{
		Name: "edge",
		Bmc:  &platformv1.BMCConfig{},
	})
	var refused ErrFieldNotSupported
	if !errors.As(err, &refused) || refused.Field != "bmc" {
		t.Fatalf("err = %v, want ErrFieldNotSupported{bmc}", err)
	}
}

func TestEncodeProfileOverridesJSON(t *testing.T) {
	out, err := EncodeProfileOverridesJSON(&platformv1.DeviceProfile{
		Name:     "edge-01",
		Role:     platformv1.DeviceRole_DEVICE_ROLE_GATEWAY,
		EkSerial: "EK-1",
		EventLog: []byte{0x01, 0x02},
	})
	if err != nil {
		t.Fatalf("EncodeProfileOverridesJSON: %v", err)
	}
	want := map[string]string{"name": "edge-01", "role": "gateway", "ek_serial": "EK-1", "event_log": "AQI="}
	for key, value := range want {
		if out[key] != value {
			t.Errorf("%s = %v, want %q", key, out[key], value)
		}
	}
	if len(out) != len(want) {
		t.Errorf("out = %v, want only the set fields", out)
	}
}

func TestEncodeProfileOverridesJSON_RefusesUnsupported(t *testing.T) {
	cases := map[string]*platformv1.DeviceProfile{
		"overrides.tenant_id":        {TenantId: "t-1"},
		"overrides.networks":         {Networks: map[string]*platformv1.NetworkPhaseConfig{"admitted": {}}},
		"overrides.platformd_config": {PlatformdConfig: &platformv1.PlatformdConfigRef{}},
	}
	for field, overrides := range cases {
		t.Run(field, func(t *testing.T) {
			_, err := EncodeProfileOverridesJSON(overrides)
			var refused ErrFieldNotSupported
			if !errors.As(err, &refused) || refused.Field != field {
				t.Fatalf("err = %v, want ErrFieldNotSupported{%s}", err, field)
			}
		})
	}
}
