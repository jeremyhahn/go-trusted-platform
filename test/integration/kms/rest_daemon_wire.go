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

//go:build integration

package kms

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The platform daemon serves the key and crypto operations through
// pkg/api/rest.KMSHandlers. Its JSON is the raw handler struct (no
// webservice envelope), byte fields are standard base64, and the int32
// enums in responses carry platform.v1 numbering (sdk/go/gen).

// daemonKMSStatusPath is the daemon's KMS backend status route.
const daemonKMSStatusPath = "/api/v1/kms/status"

// daemonPurposeUsages maps an adapter purpose to the usage names the
// daemon handler accepts in key_spec.usage.
var daemonPurposeUsages = map[string][]string{
	"encrypt": {"ENCRYPT", "DECRYPT"},
	"sign":    {"SIGN", "VERIFY"},
	"hmac":    {"GENERATE_MAC", "VERIFY_MAC"},
	"mac":     {"GENERATE_MAC", "VERIFY_MAC"},
	"wrap":    {"WRAP_KEY"},
	"derive":  {"DERIVE_KEY"},
}

// daemonAlgorithmNames maps the platform.v1 key algorithm in a daemon
// response to the adapter's algorithm string.
var daemonAlgorithmNames = map[platformv1.KMSKeyAlgorithm]string{
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048:          "RSA-2048",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_3072:          "RSA-3072",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096:          "RSA-4096",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256:        "ECDSA-P256",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384:        "ECDSA-P384",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P521:        "ECDSA-P521",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519:           "Ed25519",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128:           "AES-128-GCM",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_192:           "AES-192-GCM",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256:           "AES-256-GCM",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305: "ChaCha20-Poly1305",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA256:       "HMAC-SHA256",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA384:       "HMAC-SHA384",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA512:       "HMAC-SHA512",
}

// ErrRESTUnsupportedHash is returned when a hash algorithm name has no
// platform.v1 HashAlgorithm value to send to the daemon.
type ErrRESTUnsupportedHash struct {
	Algorithm string
}

func (e ErrRESTUnsupportedHash) Error() string {
	return "REST: unsupported hash algorithm " + e.Algorithm
}

// ErrRESTMissingInResponse is returned when a successful daemon response
// omits an object the adapter reads.
type ErrRESTMissingInResponse struct {
	Operation string
	Field     string
}

func (e ErrRESTMissingInResponse) Error() string {
	return "REST " + e.Operation + " response carries no " + e.Field
}

// handleDaemonResponse decodes a raw (non-enveloped) daemon response, or
// the daemon's ErrorResponse when the status is an error.
func (r *RESTAdapter) handleDaemonResponse(respBody []byte, statusCode int, target interface{}) error {
	if statusCode >= 400 {
		return r.parseErrorResponse(respBody, statusCode)
	}
	if err := json.Unmarshal(respBody, target); err != nil {
		return ErrRESTUnmarshalFailed{Err: err}
	}
	return nil
}

// daemonKeySpec builds the daemon key_spec for an adapter key request.
func daemonKeySpec(opts KeyGenerateOptions) restapi.KMSKeySpecRequest {
	return restapi.KMSKeySpecRequest{
		Algorithm:          strings.ToUpper(opts.Algorithm),
		Usage:              daemonPurposeUsages[strings.ToLower(opts.Purpose)],
		Exportable:         opts.Exportable,
		DeletionProtection: opts.DeletionProtection,
	}
}

// daemonHashAlgorithm converts a hash name such as "SHA-256" or
// "SHA3-256" to the platform.v1 HashAlgorithm the daemon reads. An empty
// name leaves the field unset so the daemon applies its default.
func daemonHashAlgorithm(name string) (int32, error) {
	if name == "" {
		return 0, nil
	}
	normalized := strings.ToUpper(name)
	normalized = strings.Replace(normalized, "SHA3-", "SHA3_", 1)
	normalized = strings.ReplaceAll(normalized, "-", "")
	value, ok := platformv1.HashAlgorithm_value["HASH_ALGORITHM_"+normalized]
	if !ok {
		return 0, ErrRESTUnsupportedHash{Algorithm: name}
	}
	return value, nil
}

// daemonHashName converts a platform.v1 HashAlgorithm to its short name.
func daemonHashName(value int32) string {
	return strings.TrimPrefix(platformv1.HashAlgorithm(value).String(), "HASH_ALGORITHM_")
}

// daemonAlgorithmName converts a platform.v1 key algorithm to the
// adapter's algorithm string.
func daemonAlgorithmName(value int32) string {
	if name, ok := daemonAlgorithmNames[platformv1.KMSKeyAlgorithm(value)]; ok {
		return name
	}
	return "UNSPECIFIED"
}

// daemonStatusName converts a platform.v1 KeyStatus to the adapter's
// status string.
func daemonStatusName(value int32) string {
	return strings.TrimPrefix(platformv1.KeyStatus(value).String(), "KEY_STATUS_")
}

// daemonUsageNames converts platform.v1 KeyUsage values to lower-case
// usage names.
func daemonUsageNames(values []int32) []string {
	names := make([]string, 0, len(values))
	for _, v := range values {
		name := strings.TrimPrefix(platformv1.KeyUsage(v).String(), "KEY_USAGE_")
		names = append(names, strings.ToLower(name))
	}
	return names
}

// encodeBytes base64-encodes an optional byte field; nil stays empty so
// omitempty drops it.
func encodeOptionalBytes(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}

// decodeBytes decodes a base64 byte field from a daemon response.
func decodeBytes(encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrRESTUnmarshalFailed{Err: err}
	}
	return data, nil
}
