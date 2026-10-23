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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// ErrNotJSONObject indicates a device wire payload was not a JSON object.
type ErrNotJSONObject struct {
	// Kind names the payload, e.g. "profile" or "template".
	Kind string
}

func (e ErrNotJSONObject) Error() string {
	return e.Kind + " payload is not a JSON object"
}

// ErrFieldNotSupported indicates a pb field the domain JSON shape has no
// place for. It is refused rather than dropped, so a caller never believes
// a value was stored when it was not.
type ErrFieldNotSupported struct {
	// Field is the JSON path of the refused field, e.g. "bmc".
	Field string
}

func (e ErrFieldNotSupported) Error() string {
	return "field " + e.Field + " is not supported by the device template wire shape"
}

// DeviceRoleJSON renders a pb role as the domain role string
// (DEVICE_ROLE_LOAD_BALANCER becomes "load-balancer"). An unset role
// renders empty so the server keeps its default.
func DeviceRoleJSON(role platformv1.DeviceRole) string {
	if role == platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED {
		return ""
	}
	name := strings.TrimPrefix(role.String(), "DEVICE_ROLE_")
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}

// EncodeTemplateJSON renders a pb template as the domain JSON object the
// REST handler and the device_template_create MCP tool take. The config
// is left out because the two disagree on its encoding: the caller adds
// it as bytes (REST) or YAML text (MCP).
func EncodeTemplateJSON(template *platformv1.DeviceTemplate) (map[string]any, error) {
	if template.GetBmc() != nil {
		return nil, ErrFieldNotSupported{Field: "bmc"}
	}
	out := map[string]any{}
	setString(out, "tenant_id", template.GetTenantId())
	setString(out, "name", template.GetName())
	setString(out, "description", template.GetDescription())
	setString(out, "role", DeviceRoleJSON(template.GetRole()))
	if template.GetMatchRules() != nil {
		out["match_rules"] = template.GetMatchRules()
	}
	return out, nil
}

// EncodeProfileOverridesJSON renders the overrides of a create-profile-
// from-template request as the domain JSON object both transports take.
// Only the set fields are rendered, so the template's value is kept for
// every field the caller left unset.
func EncodeProfileOverridesJSON(overrides *platformv1.DeviceProfile) (map[string]any, error) {
	for field, set := range map[string]bool{
		"tenant_id":        overrides.GetTenantId() != "",
		"networks":         len(overrides.GetNetworks()) > 0,
		"platformd_config": overrides.GetPlatformdConfig() != nil,
	} {
		if set {
			return nil, ErrFieldNotSupported{Field: "overrides." + field}
		}
	}

	out := map[string]any{}
	setString(out, "name", overrides.GetName())
	setString(out, "model", overrides.GetModel())
	setString(out, "role", DeviceRoleJSON(overrides.GetRole()))
	setString(out, "zone", overrides.GetZone())
	setString(out, "ek_serial", overrides.GetEkSerial())
	setString(out, "ek_cert", overrides.GetEkCert())
	setString(out, "mac_address", overrides.GetMacAddress())
	setString(out, "enrollment_network", overrides.GetEnrollmentNetwork())
	setString(out, "post_enrollment_network", overrides.GetPostEnrollmentNetwork())
	setString(out, "failure_network", overrides.GetFailureNetwork())
	setString(out, "tls_server_name", overrides.GetTlsServerName())
	if len(overrides.GetEventLog()) > 0 {
		out["event_log"] = base64.StdEncoding.EncodeToString(overrides.GetEventLog())
	}
	if overrides.GetMatchRules() != nil {
		out["match_rules"] = overrides.GetMatchRules()
	}
	return out, nil
}

// setString sets key only when value is non-empty, so an unset pb field
// is absent from the JSON object rather than sent as "".
func setString(obj map[string]any, key, value string) {
	if value != "" {
		obj[key] = value
	}
}

// DecodeProfileJSON decodes a device profile in its domain JSON shape —
// the shape the REST handlers and MCP profile tools return — into the pb
// DeviceProfile.
func DecodeProfileJSON(data []byte) (*platformv1.DeviceProfile, error) {
	obj, err := decodeJSONObject(data, "profile")
	if err != nil {
		return nil, err
	}
	restwire.NormalizeProfileJSON(obj)

	profile := &platformv1.DeviceProfile{}
	if err := objectToProto(obj, profile); err != nil {
		return nil, err
	}
	return profile, nil
}

// DecodeTemplateJSON decodes a device template in the REST JSON shape,
// with config as base64 bytes, into the pb DeviceTemplate.
func DecodeTemplateJSON(data []byte) (*platformv1.DeviceTemplate, error) {
	return decodeTemplateJSON(data, false)
}

// DecodeTemplateToolJSON decodes a device template in the shape the
// device_template_create MCP tool returns, with config as YAML text, into
// the pb DeviceTemplate.
func DecodeTemplateToolJSON(data []byte) (*platformv1.DeviceTemplate, error) {
	return decodeTemplateJSON(data, true)
}

func decodeTemplateJSON(data []byte, configIsText bool) (*platformv1.DeviceTemplate, error) {
	obj, err := decodeJSONObject(data, "template")
	if err != nil {
		return nil, err
	}

	if role, ok := obj["role"].(string); ok {
		obj["role"] = restwire.DeviceRoleFromJSON(role).String()
	}
	// The pb config field is bytes, so protojson wants base64.
	if config, ok := obj["config"].(string); ok && configIsText {
		obj["config"] = base64.StdEncoding.EncodeToString([]byte(config))
	}
	for _, key := range []string{"created_at", "updated_at"} {
		if ts, ok := obj[key].(string); ok && ts == restwire.ZeroRFC3339 {
			delete(obj, key)
		}
	}

	template := &platformv1.DeviceTemplate{}
	if err := objectToProto(obj, template); err != nil {
		return nil, err
	}
	return template, nil
}

// decodeJSONObject decodes data as a JSON object, keeping numbers exact so
// uint64 ids survive past 2^53.
func decodeJSONObject(data []byte, kind string) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var obj map[string]any
	if err := decoder.Decode(&obj); err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, ErrNotJSONObject{Kind: kind}
	}
	return obj, nil
}

// objectToProto re-encodes a normalized JSON object into msg, discarding
// domain-only fields the pb message does not carry.
func objectToProto(obj map[string]any, msg proto.Message) error {
	normalized, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(normalized, msg)
}
