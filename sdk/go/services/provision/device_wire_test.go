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

func TestDecodeProfileJSON(t *testing.T) {
	profile, err := DecodeProfileJSON([]byte(`{
		"id": "9007199254740993",
		"name": "gw-01",
		"role": "gateway",
		"ek_serial": "EK-1",
		"config": {"hostname": "gw-01"},
		"created_at": "0001-01-01T00:00:00Z",
		"domain_only": true
	}`))
	if err != nil {
		t.Fatalf("DecodeProfileJSON: %v", err)
	}
	if profile.GetId() != 9007199254740993 {
		t.Errorf("id = %d, want the exact uint64", profile.GetId())
	}
	if profile.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_GATEWAY {
		t.Errorf("role = %v, want gateway", profile.GetRole())
	}
	if profile.GetName() != "gw-01" || profile.GetEkSerial() != "EK-1" {
		t.Errorf("profile = %v", profile)
	}
}

func TestDecodeTemplateJSON(t *testing.T) {
	template, err := DecodeTemplateJSON([]byte(`{
		"id": 18446744073709551615,
		"name": "edge",
		"role": "control-plane",
		"config": "aG9zdG5hbWU6IGVkZ2UtMDEK",
		"match_rules": {"mac_prefix": "00:25:90"},
		"created_at": "2026-10-12T09:00:00Z",
		"updated_at": "0001-01-01T00:00:00Z"
	}`))
	if err != nil {
		t.Fatalf("DecodeTemplateJSON: %v", err)
	}
	if template.GetId() != 18446744073709551615 {
		t.Errorf("id = %d, want the exact uint64 from a JSON number", template.GetId())
	}
	if template.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_CONTROL_PLANE {
		t.Errorf("role = %v, want control plane", template.GetRole())
	}
	if string(template.GetConfig()) != "hostname: edge-01\n" {
		t.Errorf("config = %q, want the base64 decoded once", template.GetConfig())
	}
	if template.GetMatchRules().GetMacPrefix() != "00:25:90" {
		t.Errorf("match rules = %v", template.GetMatchRules())
	}
	if template.GetCreatedAt() == nil {
		t.Error("a real created_at must be kept")
	}
	if template.GetUpdatedAt() != nil {
		t.Error("a zero updated_at must be dropped")
	}
}

func TestDecodeTemplateToolJSON(t *testing.T) {
	template, err := DecodeTemplateToolJSON([]byte(`{"id": "7", "name": "edge", "config": "hostname: edge-01\n"}`))
	if err != nil {
		t.Fatalf("DecodeTemplateToolJSON: %v", err)
	}
	if template.GetId() != 7 {
		t.Errorf("id = %d, want 7 from the decimal string", template.GetId())
	}
	if string(template.GetConfig()) != "hostname: edge-01\n" {
		t.Errorf("config = %q, want the YAML text as bytes", template.GetConfig())
	}
}

func TestDecodeTemplateJSON_UnknownRole(t *testing.T) {
	template, err := DecodeTemplateJSON([]byte(`{"name": "x", "role": "toaster"}`))
	if err != nil {
		t.Fatalf("DecodeTemplateJSON: %v", err)
	}
	if template.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_UNKNOWN {
		t.Errorf("role = %v, want unknown", template.GetRole())
	}
}

func TestDeviceWireDecode_Errors(t *testing.T) {
	decoders := map[string]func([]byte) error{
		"profile": func(data []byte) error {
			_, err := DecodeProfileJSON(data)
			return err
		},
		"template": func(data []byte) error {
			_, err := DecodeTemplateJSON(data)
			return err
		},
	}
	decodeTool := func(data []byte) error {
		_, err := DecodeTemplateToolJSON(data)
		return err
	}

	t.Run("template-tool/NotAnObject", func(t *testing.T) {
		var notObject ErrNotJSONObject
		if err := decodeTool([]byte(`null`)); !errors.As(err, &notObject) {
			t.Errorf("err = %v, want ErrNotJSONObject", err)
		}
	})
	t.Run("template/ConfigNotBase64", func(t *testing.T) {
		if err := decoders["template"]([]byte(`{"config": "hostname: edge-01\n"}`)); err == nil {
			t.Error("YAML text in the REST shape must not decode as bytes")
		}
	})

	for kind, decode := range decoders {
		t.Run(kind+"/NotAnObject", func(t *testing.T) {
			var notObject ErrNotJSONObject
			if err := decode([]byte(`null`)); !errors.As(err, &notObject) || notObject.Kind != kind {
				t.Errorf("err = %v, want ErrNotJSONObject{%s}", err, kind)
			}
		})
		t.Run(kind+"/MalformedJSON", func(t *testing.T) {
			if err := decode([]byte(`{"name":`)); err == nil {
				t.Error("expected a decode error")
			}
		})
		t.Run(kind+"/WrongFieldType", func(t *testing.T) {
			if err := decode([]byte(`{"name": 42}`)); err == nil {
				t.Error("expected a protojson error for a numeric name")
			}
		})
	}
}
