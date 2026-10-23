// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package restwire

import (
	"encoding/base64"
	"encoding/json"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Device profiles travel as JSON objects on the REST and MCP transports, in
// the domain shape (entities.DeviceProfile) or the webservice shape
// (device.ProfileFullResponse). Both differ from the protojson encoding of
// platform.v1 DeviceProfile in the same places: role and auth_method are
// lower-case domain strings rather than enum names, and config is a JSON
// value rather than bytes. The helpers here are the one translation of those
// fields for every SDK decoder and encoder.

// ZeroRFC3339 is the JSON encoding of Go's zero time.Time, which the servers
// emit for an unassigned profile's assigned_at.
const ZeroRFC3339 = "0001-01-01T00:00:00Z"

// deviceRoles maps the entities.DeviceRole JSON strings to the platform.v1
// DeviceRole enum, mirroring pkg/api/grpc entityRoleToProtoMap.
var deviceRoles = map[string]platformv1.DeviceRole{
	"unknown":       platformv1.DeviceRole_DEVICE_ROLE_UNKNOWN,
	"server":        platformv1.DeviceRole_DEVICE_ROLE_SERVER,
	"client":        platformv1.DeviceRole_DEVICE_ROLE_CLIENT,
	"workstation":   platformv1.DeviceRole_DEVICE_ROLE_WORKSTATION,
	"edge":          platformv1.DeviceRole_DEVICE_ROLE_EDGE,
	"iot":           platformv1.DeviceRole_DEVICE_ROLE_IOT,
	"gateway":       platformv1.DeviceRole_DEVICE_ROLE_GATEWAY,
	"load-balancer": platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER,
	"control-plane": platformv1.DeviceRole_DEVICE_ROLE_CONTROL_PLANE,
	"worker":        platformv1.DeviceRole_DEVICE_ROLE_WORKER,
}

// deviceRoleNames is the inverse of deviceRoles.
var deviceRoleNames = invert(deviceRoles)

// authMethods maps the entities.AuthMethod JSON strings to the platform.v1
// AuthMethod enum, mirroring DeviceGRPCService.authMethodToPb.
var authMethods = map[string]platformv1.AuthMethod{
	"none":   platformv1.AuthMethod_AUTH_METHOD_NONE,
	"802.1x": platformv1.AuthMethod_AUTH_METHOD_802_1X,
}

// authMethodNames is the inverse of authMethods.
var authMethodNames = invert(authMethods)

func invert[E comparable](forward map[string]E) map[E]string {
	inverse := make(map[E]string, len(forward))
	for name, value := range forward {
		inverse[value] = name
	}
	return inverse
}

// DeviceRoleFromJSON returns the enum for a domain role string. A string the
// SDK does not know maps to DEVICE_ROLE_UNKNOWN, as it does on the server.
func DeviceRoleFromJSON(role string) platformv1.DeviceRole {
	if mapped, ok := deviceRoles[role]; ok {
		return mapped
	}
	return platformv1.DeviceRole_DEVICE_ROLE_UNKNOWN
}

// DeviceRoleToJSON returns the domain role string for an enum. ok is false
// for DEVICE_ROLE_UNSPECIFIED and any value the domain has no string for, so
// the caller omits the field and the server applies its default.
func DeviceRoleToJSON(role platformv1.DeviceRole) (name string, ok bool) {
	name, ok = deviceRoleNames[role]
	return name, ok
}

// AuthMethodFromJSON returns the enum for a domain auth-method string.
// Everything except "802.1x" maps to AUTH_METHOD_NONE, as it does on the
// server.
func AuthMethodFromJSON(method string) platformv1.AuthMethod {
	if mapped, ok := authMethods[method]; ok {
		return mapped
	}
	return platformv1.AuthMethod_AUTH_METHOD_NONE
}

// AuthMethodToJSON returns the domain auth-method string for an enum. ok is
// false for AUTH_METHOD_UNSPECIFIED.
func AuthMethodToJSON(method platformv1.AuthMethod) (name string, ok bool) {
	name, ok = authMethodNames[method]
	return name, ok
}

// NormalizeProfileJSON rewrites a decoded domain or webservice profile object
// in place into the shape protojson decodes as platform.v1 DeviceProfile:
//
//   - role and every network's auth_method become enum names;
//   - config, an arbitrary JSON value, becomes base64 of its JSON encoding,
//     exactly as the gRPC converter fills the bytes field; null is dropped;
//   - a zero assigned_at ("never assigned") is dropped, as the gRPC converter
//     leaves the field unset;
//   - the domain "platformd" key is renamed platformd_config, its inline
//     value carried as base64 bytes.
//
// Decode the object with json.Decoder.UseNumber so uint64 ids survive.
func NormalizeProfileJSON(profile map[string]any) {
	if role, ok := profile["role"].(string); ok {
		profile["role"] = DeviceRoleFromJSON(role).String()
	}

	if config, present := profile["config"]; present {
		if encoded, ok := jsonAsBytes(config); ok {
			profile["config"] = encoded
		} else {
			delete(profile, "config")
		}
	}

	if assignedAt, ok := profile["assigned_at"].(string); ok && assignedAt == ZeroRFC3339 {
		delete(profile, "assigned_at")
	}

	if networks, ok := profile["networks"].(map[string]any); ok {
		for _, v := range networks {
			network, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if method, ok := network["auth_method"].(string); ok {
				network["auth_method"] = AuthMethodFromJSON(method).String()
			}
		}
	}

	if platformd, ok := profile["platformd"].(map[string]any); ok {
		if inline, present := platformd["inline"]; present {
			if _, isString := inline.(string); !isString {
				if encoded, ok := jsonAsBytes(inline); ok {
					platformd["inline"] = encoded
				} else {
					delete(platformd, "inline")
				}
			}
		}
		profile["platformd_config"] = platformd
		delete(profile, "platformd")
	}
}

// jsonAsBytes returns the protojson bytes encoding (base64) of a JSON value's
// encoding. ok is false for null and for a value that does not encode.
func jsonAsBytes(value any) (string, bool) {
	if value == nil {
		return "", false
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	return base64.StdEncoding.EncodeToString(encoded), true
}
