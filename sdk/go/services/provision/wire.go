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

package provision

// This file maps the config-delivery JSON wire shapes served by the REST
// handler (pkg/provisioning/configdelivery/types.go) and the MCP provision_*
// tools (pkg/api/mcp/provision_tools.go) onto the platform.v1 protobuf
// response messages. Both transports serve the domain JSON types, not
// protojson-encoded pb messages, so the SDK REST and MCP adapters delegate
// here instead of decoding directly into the pb types.
//
// Pending detection follows the server contract exactly:
//   - FetchConfig: pending iff the payload has no "config" key (a pending
//     payload carries session_id / provision_url / poll_interval_seconds).
//   - PollSession: pending iff status == "pending" and no "config" key.
//
// Session objects are the domain configdelivery.Session JSON shape. The
// embedded device profile is domain JSON (entities.DeviceProfile), which
// differs from the pb DeviceProfile in two enum fields (role, auth_method)
// and two object-vs-bytes fields (config, platformd.inline key name), so
// sessionJSONToProto normalizes those before a protojson decode.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"

	"google.golang.org/protobuf/encoding/protojson"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// pollSessionPendingStatus is the status string the server returns for a
// not-yet-fulfilled session on both the REST and MCP transports.
const pollSessionPendingStatus = "pending"

// zeroRFC3339 is the JSON encoding of Go's zero time.Time, emitted by the
// REST/MCP transports for an unassigned profile's assigned_at field.
const zeroRFC3339 = "0001-01-01T00:00:00Z"

// fetchConfigPendingJSON carries the pending-session arm of a FetchConfig
// response (configdelivery.PendingResponse).
type fetchConfigPendingJSON struct {
	SessionID           string `json:"session_id"`
	ProvisionURL        string `json:"provision_url"`
	PollIntervalSeconds int32  `json:"poll_interval_seconds"`
}

// deliveredConfigJSON carries the delivered-config arm of a FetchConfig or
// PollSession response (configdelivery.ConfigResponse). Config is kept raw so
// the exact JSON bytes flow into DeliveredConfig.config_json, matching the
// gRPC server's json.Marshal(resp.Config) encoding.
type deliveredConfigJSON struct {
	Config json.RawMessage `json:"config"`
	Status string          `json:"status"`
}

// DecodeFetchConfigJSON decodes the REST/MCP JSON wire form of a FetchConfig
// response into the platform.v1 oneof message. A payload without a "config"
// key is a pending interactive provisioning session.
func DecodeFetchConfigJSON(data []byte) (*platformv1.FetchConfigResponse, error) {
	keys, err := topLevelKeys(data)
	if err != nil {
		return nil, &ErrWireDecodeFailed{Op: "FetchConfig", Cause: err}
	}

	if _, delivered := keys["config"]; !delivered {
		var pending fetchConfigPendingJSON
		if err := json.Unmarshal(data, &pending); err != nil {
			return nil, &ErrWireDecodeFailed{Op: "FetchConfig", Cause: err}
		}
		return &platformv1.FetchConfigResponse{
			Result: &platformv1.FetchConfigResponse_Pending{
				Pending: &platformv1.PendingSession{
					SessionId:           pending.SessionID,
					ProvisionUrl:        pending.ProvisionURL,
					PollIntervalSeconds: pending.PollIntervalSeconds,
				},
			},
		}, nil
	}

	deliveredCfg, err := decodeDeliveredConfig(data)
	if err != nil {
		return nil, &ErrWireDecodeFailed{Op: "FetchConfig", Cause: err}
	}
	return &platformv1.FetchConfigResponse{
		Result: &platformv1.FetchConfigResponse_Delivered{
			Delivered: deliveredCfg,
		},
	}, nil
}

// DecodePollSessionJSON decodes the REST/MCP JSON wire form of a PollSession
// response into the platform.v1 oneof message. A payload without a "config"
// key is a pending status marker.
func DecodePollSessionJSON(data []byte) (*platformv1.PollSessionResponse, error) {
	keys, err := topLevelKeys(data)
	if err != nil {
		return nil, &ErrWireDecodeFailed{Op: "PollSession", Cause: err}
	}

	if _, delivered := keys["config"]; !delivered {
		var pending struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(data, &pending); err != nil {
			return nil, &ErrWireDecodeFailed{Op: "PollSession", Cause: err}
		}
		if pending.Status == "" {
			pending.Status = pollSessionPendingStatus
		}
		return &platformv1.PollSessionResponse{
			Result: &platformv1.PollSessionResponse_PendingStatus{
				PendingStatus: pending.Status,
			},
		}, nil
	}

	deliveredCfg, err := decodeDeliveredConfig(data)
	if err != nil {
		return nil, &ErrWireDecodeFailed{Op: "PollSession", Cause: err}
	}
	return &platformv1.PollSessionResponse{
		Result: &platformv1.PollSessionResponse_Delivered{
			Delivered: deliveredCfg,
		},
	}, nil
}

// DecodeListSessionsJSON decodes the REST/MCP JSON wire form of a session
// list into the platform.v1 message. REST serves a bare JSON array; MCP
// serves an object with a "sessions" key. Both forms are accepted.
func DecodeListSessionsJSON(data []byte) (*platformv1.ListSessionsResponse, error) {
	if len(data) == 0 || string(data) == "null" {
		return &platformv1.ListSessionsResponse{}, nil
	}
	raw, err := unwrapKey(data, "sessions")
	if err != nil {
		return nil, &ErrWireDecodeFailed{Op: "ListSessions", Cause: err}
	}

	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, &ErrWireDecodeFailed{Op: "ListSessions", Cause: err}
	}

	sessions := make([]*platformv1.ProvisioningSession, 0, len(items))
	for _, item := range items {
		session, err := sessionJSONToProto(item)
		if err != nil {
			return nil, &ErrWireDecodeFailed{Op: "ListSessions", Cause: err}
		}
		sessions = append(sessions, session)
	}
	return &platformv1.ListSessionsResponse{Sessions: sessions}, nil
}

// DecodeGetSessionJSON decodes the REST/MCP JSON wire form of a single
// session into the platform.v1 message. REST serves a bare session object;
// MCP serves an object with a "session" key. Both forms are accepted.
func DecodeGetSessionJSON(data []byte) (*platformv1.GetSessionResponse, error) {
	raw, err := unwrapKey(data, "session")
	if err != nil {
		return nil, &ErrWireDecodeFailed{Op: "GetSession", Cause: err}
	}
	session, err := sessionJSONToProto(raw)
	if err != nil {
		return nil, &ErrWireDecodeFailed{Op: "GetSession", Cause: err}
	}
	return &platformv1.GetSessionResponse{Session: session}, nil
}

// decodeDeliveredConfig extracts the delivered-config fields from a JSON
// payload known to carry a "config" key.
func decodeDeliveredConfig(data []byte) (*platformv1.DeliveredConfig, error) {
	var delivered deliveredConfigJSON
	if err := json.Unmarshal(data, &delivered); err != nil {
		return nil, err
	}
	return &platformv1.DeliveredConfig{
		ConfigJson: delivered.Config,
		Status:     delivered.Status,
	}, nil
}

// topLevelKeys parses data as a JSON object and returns its top-level keys.
func topLevelKeys(data []byte) (map[string]json.RawMessage, error) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// unwrapKey returns the value of the named key when data is a JSON object
// carrying it (the MCP wrapping) and data itself otherwise (the bare REST
// form). A JSON object without the key is an error for the session shapes,
// which never serve bare objects with neither form — except a bare session
// object, which is detected by the absence of the wrapper key alongside
// object payloads that ARE the session itself. To keep detection exact, the
// wrapper form is only assumed when the object has exactly the named key.
func unwrapKey(data []byte, key string) (json.RawMessage, error) {
	trimmed := firstNonSpace(data)
	if trimmed != '{' {
		// Bare array (list) or other non-object form: pass through.
		return data, nil
	}
	keys, err := topLevelKeys(data)
	if err != nil {
		return nil, err
	}
	if inner, ok := keys[key]; ok && len(keys) == 1 {
		return inner, nil
	}
	return data, nil
}

// firstNonSpace returns the first non-whitespace byte of data, or 0 when
// data is empty or all whitespace.
func firstNonSpace(data []byte) byte {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return b
		}
	}
	return 0
}

// deviceRoleJSONToEnum maps the domain entities.DeviceRole JSON strings to
// the platform.v1 DeviceRole enum value names protojson expects. The mapping
// mirrors pkg/api/grpc EntityRoleToProto exactly (unknown strings map to
// DEVICE_ROLE_UNKNOWN).
var deviceRoleJSONToEnum = map[string]string{
	"unknown":       "DEVICE_ROLE_UNKNOWN",
	"server":        "DEVICE_ROLE_SERVER",
	"client":        "DEVICE_ROLE_CLIENT",
	"workstation":   "DEVICE_ROLE_WORKSTATION",
	"edge":          "DEVICE_ROLE_EDGE",
	"iot":           "DEVICE_ROLE_IOT",
	"gateway":       "DEVICE_ROLE_GATEWAY",
	"load-balancer": "DEVICE_ROLE_LOAD_BALANCER",
	"control-plane": "DEVICE_ROLE_CONTROL_PLANE",
	"worker":        "DEVICE_ROLE_WORKER",
}

// authMethodJSONToEnum maps the domain entities.AuthMethod JSON strings to
// the platform.v1 AuthMethod enum value names. The mapping mirrors
// DeviceGRPCService.authMethodToPb exactly (everything except "802.1x" maps
// to AUTH_METHOD_NONE).
var authMethodJSONToEnum = map[string]string{
	"none":   "AUTH_METHOD_NONE",
	"802.1x": "AUTH_METHOD_802_1X",
}

// errSessionNotObject indicates a session wire payload was not a JSON object.
var errSessionNotObject = errors.New("session payload is not a JSON object")

// sessionJSONToProto converts a domain configdelivery.Session JSON object
// into a platform.v1 ProvisioningSession. The scalar session fields and
// RFC3339 timestamps decode via protojson directly (the JSON keys match the
// proto field names); the embedded device profile is normalized first so its
// domain enum strings and object-typed fields fit the pb schema.
func sessionJSONToProto(data []byte) (*platformv1.ProvisioningSession, error) {
	// UseNumber preserves uint64 IDs (profile_id) exactly; a plain
	// interface{} decode would round-trip them through float64 and lose
	// precision past 2^53.
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var obj map[string]any
	if err := decoder.Decode(&obj); err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, errSessionNotObject
	}

	if profile, ok := obj["profile"].(map[string]any); ok {
		normalizeProfileJSON(profile)
	}

	normalized, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	session := &platformv1.ProvisioningSession{}
	unmarshal := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := unmarshal.Unmarshal(normalized, session); err != nil {
		return nil, err
	}
	return session, nil
}

// normalizeProfileJSON rewrites a domain entities.DeviceProfile JSON object
// in place so it decodes into the pb DeviceProfile via protojson:
//
//   - role: domain lowercase string -> pb enum value name
//   - networks[*].auth_method: domain string -> pb enum value name
//   - config: domain JSON value -> base64(JSON) to fit the pb bytes field,
//     matching the gRPC profileToPb converter's json.Marshal(p.Config)
//   - assigned_at: dropped when it is the zero time, matching the gRPC
//     converter's IsZero guard (an unassigned profile has no timestamp)
//   - platformd: renamed to platformd_config; its object-typed "inline"
//     value becomes base64(JSON) to fit the pb bytes field
//
// The domain ek_cert key needs no handling: it matches the pb DeviceProfile
// ek_cert field name, so protojson decodes the prestaged EK certificate
// directly and it survives the cross-transport round trip. The domain-only
// workload_pcr field has no pb counterpart and is dropped by protojson's
// DiscardUnknown.
func normalizeProfileJSON(profile map[string]any) {
	if role, ok := profile["role"].(string); ok {
		mapped, known := deviceRoleJSONToEnum[role]
		if !known {
			mapped = "DEVICE_ROLE_UNKNOWN"
		}
		profile["role"] = mapped
	}

	// The full merged device config is an arbitrary JSON value; the pb
	// DeviceProfile.config bytes field carries its JSON encoding, exactly
	// as the gRPC converter serializes the domain config.
	if config, present := profile["config"]; present {
		if config == nil {
			delete(profile, "config")
		} else if encoded, err := json.Marshal(config); err == nil {
			profile["config"] = base64.StdEncoding.EncodeToString(encoded)
		} else {
			delete(profile, "config")
		}
	}

	// A zero assignment timestamp means "never assigned"; the gRPC
	// converter leaves the pb field unset, so drop it here for parity.
	if assignedAt, ok := profile["assigned_at"].(string); ok && assignedAt == zeroRFC3339 {
		delete(profile, "assigned_at")
	}

	if networks, ok := profile["networks"].(map[string]any); ok {
		for _, v := range networks {
			network, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if method, ok := network["auth_method"].(string); ok {
				mapped, known := authMethodJSONToEnum[method]
				if !known {
					mapped = "AUTH_METHOD_NONE"
				}
				network["auth_method"] = mapped
			}
		}
	}

	if platformd, ok := profile["platformd"].(map[string]any); ok {
		if inline, present := platformd["inline"]; present {
			if _, isString := inline.(string); !isString {
				encoded, err := json.Marshal(inline)
				if err == nil {
					platformd["inline"] = base64.StdEncoding.EncodeToString(encoded)
				} else {
					delete(platformd, "inline")
				}
			}
		}
		profile["platformd_config"] = platformd
		delete(profile, "platformd")
	}
}
