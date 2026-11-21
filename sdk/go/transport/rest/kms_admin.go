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

package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The KMS key-admin routes of the webservice KMS router
// (pkg/webservice/v1/rest/kms/router.go): ImportKey, UpdateKeyStatus,
// GetKeyVersions and BackendStatus (#1948, #452). The server names
// algorithms, usages and statuses as strings; the codecs here translate
// them to and from the proto enums.

// kmsKeyStatusNames is the server's name for each proto KeyStatus a client
// may set. DESTROYED is the server's DELETED; PENDING_IMPORT has no server
// name and is refused before the wire.
var kmsKeyStatusNames = map[platformv1.KeyStatus]string{
	platformv1.KeyStatus_KEY_STATUS_ENABLED:          "ENABLED",
	platformv1.KeyStatus_KEY_STATUS_DISABLED:         "DISABLED",
	platformv1.KeyStatus_KEY_STATUS_PENDING_DELETION: "PENDING_DELETION",
	platformv1.KeyStatus_KEY_STATUS_DESTROYED:        "DELETED",
}

// kmsKeyStatusesByName reads a server status back as the proto KeyStatus,
// the way the gRPC daemon does (pkg/api/daemon/kms_platform_service.go):
// ROTATING reads as ENABLED and COMPROMISED as DISABLED. An unknown name
// reads as UNSPECIFIED.
var kmsKeyStatusesByName = map[string]platformv1.KeyStatus{
	"ENABLED":          platformv1.KeyStatus_KEY_STATUS_ENABLED,
	"DISABLED":         platformv1.KeyStatus_KEY_STATUS_DISABLED,
	"PENDING_DELETION": platformv1.KeyStatus_KEY_STATUS_PENDING_DELETION,
	"DELETED":          platformv1.KeyStatus_KEY_STATUS_DESTROYED,
	"ROTATING":         platformv1.KeyStatus_KEY_STATUS_ENABLED,
	"COMPROMISED":      platformv1.KeyStatus_KEY_STATUS_DISABLED,
}

func init() {
	templatedRouteTable[platformv1.KeyManagementService_ImportKey_FullMethodName] = templatedRoute{
		path:   "/api/v1/kms/keys/import",
		method: http.MethodPost,
	}
	templatedRouteTable[platformv1.KeyManagementService_UpdateKeyStatus_FullMethodName] =
		itemRoute("/api/v1/kms/keys/{name}/status", http.MethodPut, "{name}", "key_id")
	templatedRouteTable[platformv1.KeyManagementService_GetKeyVersions_FullMethodName] =
		itemRoute("/api/v1/kms/keys/{name}/versions", http.MethodGet, "{name}", "key_id")
	templatedRouteTable[platformv1.KeyManagementService_BackendStatus_FullMethodName] = templatedRoute{
		path:   "/api/v1/kms/backend/status",
		method: http.MethodGet,
	}

	restRequestEncoders[platformv1.KeyManagementService_ImportKey_FullMethodName] =
		requestEncoder(platformv1.KeyManagementService_ImportKey_FullMethodName, encodeKMSImportKey)
	restRequestEncoders[platformv1.KeyManagementService_UpdateKeyStatus_FullMethodName] =
		requestEncoder(platformv1.KeyManagementService_UpdateKeyStatus_FullMethodName, encodeKMSUpdateKeyStatus)
	restRequestEncoders[platformv1.KeyManagementService_GetKeyVersions_FullMethodName] = encodeKMSGetKeyVersions
	restRequestEncoders[platformv1.KeyManagementService_BackendStatus_FullMethodName] =
		requestEncoder(platformv1.KeyManagementService_BackendStatus_FullMethodName,
			func(*platformv1.BackendStatusRequest) (map[string]interface{}, error) { return nil, nil })

	restResponseDecoders[platformv1.KeyManagementService_ImportKey_FullMethodName] =
		wireDecoder(platformv1.KeyManagementService_ImportKey_FullMethodName, decodeKMSImportKey)
	restResponseDecoders[platformv1.KeyManagementService_UpdateKeyStatus_FullMethodName] =
		wireDecoder(platformv1.KeyManagementService_UpdateKeyStatus_FullMethodName, decodeKMSUpdateKeyStatus)
	restResponseDecoders[platformv1.KeyManagementService_GetKeyVersions_FullMethodName] =
		wireDecoder(platformv1.KeyManagementService_GetKeyVersions_FullMethodName, decodeKMSGetKeyVersions)
	restResponseDecoders[platformv1.KeyManagementService_BackendStatus_FullMethodName] =
		wireDecoder(platformv1.KeyManagementService_BackendStatus_FullMethodName, decodeKMSBackendStatus)

	// The versions route answers only the list; the key it lists is the
	// request's.
	restReplyCompleters[platformv1.KeyManagementService_GetKeyVersions_FullMethodName] = func(args, reply interface{}) {
		req, okReq := args.(*platformv1.GetKeyVersionsRequest)
		resp, okResp := reply.(*platformv1.GetKeyVersionsResponse)
		if okReq && okResp && req != nil && resp != nil && resp.GetKeyId() == "" {
			resp.KeyId = req.GetKeyId()
		}
	}
}

// encodeKMSImportKey builds the server's ImportKeyRequest: the algorithm
// and usages by the server's names.
func encodeKMSImportKey(req *platformv1.ImportKeyRequest) (map[string]interface{}, error) {
	body := map[string]interface{}{"name": req.GetName()}
	spec := req.GetKeySpec()
	if alg := spec.GetAlgorithm(); alg != platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED {
		name, ok := kmsKeyAlgorithmNames[alg]
		if !ok {
			return nil, ErrKeyAlgorithmNotSupported{Algorithm: alg.String()}
		}
		body["algorithm"] = name
	}
	usages := make([]string, 0, len(spec.GetUsage()))
	for _, usage := range spec.GetUsage() {
		name, ok := kmsKeyUsageNames[usage]
		if !ok {
			return nil, ErrKeyUsageNotSupported{Usage: usage.String()}
		}
		usages = append(usages, name)
	}
	if len(usages) > 0 {
		body["usage"] = usages
	}
	if len(req.GetKeyMaterial()) > 0 {
		body["key_material"] = req.GetKeyMaterial()
	}
	if req.GetWrappingKeyId() != "" {
		body["wrapping_key_id"] = req.GetWrappingKeyId()
	}
	if req.GetDescription() != "" {
		body["description"] = req.GetDescription()
	}
	if len(req.GetTags()) > 0 {
		body["tags"] = req.GetTags()
	}
	return body, nil
}

// encodeKMSUpdateKeyStatus builds the server's UpdateKeyStatusRequest. A
// status the server has no name for (PENDING_IMPORT, UNSPECIFIED) is
// refused.
func encodeKMSUpdateKeyStatus(req *platformv1.UpdateKeyStatusRequest) (map[string]interface{}, error) {
	name, ok := kmsKeyStatusNames[req.GetStatus()]
	if !ok {
		return nil, fmt.Errorf("key status %s has no REST name", req.GetStatus())
	}
	body := map[string]interface{}{"status": name}
	if req.GetVersion() != 0 {
		body["version"] = req.GetVersion()
	}
	return body, nil
}

// encodeKMSGetKeyVersions sends no body: the key is in the path, and the
// route pages nothing, so a limit or a cursor is refused rather than
// silently ignored.
func encodeKMSGetKeyVersions(body interface{}) (interface{}, error) {
	req, ok := body.(*platformv1.GetKeyVersionsRequest)
	if !ok || req == nil {
		return nil, ErrUnexpectedRequestType{Method: platformv1.KeyManagementService_GetKeyVersions_FullMethodName}
	}
	if req.GetLimit() != 0 || req.GetCursor() != "" {
		return nil, fmt.Errorf("GetKeyVersions over REST does not page: limit and cursor must be unset")
	}
	return nil, nil
}

type kmsImportKeyReply struct {
	KeyID     string `json:"key_id"`
	Version   uint64 `json:"version"`
	Algorithm string `json:"algorithm"`
}

func decodeKMSImportKey(raw []byte) (*platformv1.ImportKeyResponse, error) {
	var reply kmsImportKeyReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	alg := kmsKeyAlgorithmsByName[reply.Algorithm]
	return &platformv1.ImportKeyResponse{
		Status: &platformv1.Status{Success: true},
		Key: &platformv1.KMSKeyHandle{
			KeyId:     reply.KeyID,
			Version:   reply.Version,
			Algorithm: alg,
		},
		Metadata: &platformv1.KMSKeyMetadata{
			KeyId:     reply.KeyID,
			Version:   reply.Version,
			Algorithm: alg,
		},
	}, nil
}

type kmsUpdateKeyStatusReply struct {
	KeyID   string `json:"key_id"`
	Version uint64 `json:"version"`
	Status  string `json:"status"`
}

func decodeKMSUpdateKeyStatus(raw []byte) (*platformv1.UpdateKeyStatusResponse, error) {
	var reply kmsUpdateKeyStatusReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return &platformv1.UpdateKeyStatusResponse{
		Status:    &platformv1.Status{Success: true},
		KeyId:     reply.KeyID,
		Version:   reply.Version,
		KeyStatus: kmsKeyStatusesByName[reply.Status],
	}, nil
}

type kmsKeyVersionsReply struct {
	Versions []struct {
		Version    uint64    `json:"version"`
		Status     string    `json:"status"`
		Algorithm  string    `json:"algorithm"`
		CreatedAt  time.Time `json:"created_at"`
		DisabledAt time.Time `json:"disabled_at"`
	} `json:"versions"`
}

// kmsUnixSeconds is t in unix seconds, and 0 for the zero time.
func kmsUnixSeconds(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func decodeKMSGetKeyVersions(raw []byte) (*platformv1.GetKeyVersionsResponse, error) {
	var reply kmsKeyVersionsReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	out := &platformv1.GetKeyVersionsResponse{
		Versions: make([]*platformv1.KMSKeyVersionInfo, 0, len(reply.Versions)),
	}
	for _, v := range reply.Versions {
		out.Versions = append(out.Versions, &platformv1.KMSKeyVersionInfo{
			Version:    v.Version,
			Status:     kmsKeyStatusesByName[v.Status],
			Algorithm:  kmsKeyAlgorithmsByName[v.Algorithm],
			CreatedAt:  kmsUnixSeconds(v.CreatedAt),
			DisabledAt: kmsUnixSeconds(v.DisabledAt),
		})
	}
	return out, nil
}

type kmsBackendStatusReply struct {
	BackendType  string          `json:"backend_type"`
	Status       string          `json:"status"`
	Device       string          `json:"device"`
	Region       string          `json:"region"`
	KeyID        string          `json:"key_id"`
	PCRBanks     []string        `json:"pcr_banks"`
	PCRRegisters []int32         `json:"pcr_registers"`
	Capabilities map[string]bool `json:"capabilities"`
}

func decodeKMSBackendStatus(raw []byte) (*platformv1.BackendStatusResponse, error) {
	var reply kmsBackendStatusReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return &platformv1.BackendStatusResponse{
		Status:        &platformv1.Status{Success: true},
		BackendType:   reply.BackendType,
		BackendStatus: reply.Status,
		Device:        reply.Device,
		Region:        reply.Region,
		KeyId:         reply.KeyID,
		PcrBanks:      reply.PCRBanks,
		PcrRegisters:  reply.PCRRegisters,
		Capabilities:  reply.Capabilities,
	}, nil
}
