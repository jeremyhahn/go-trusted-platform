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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The KMS key-generation routes (docs/kms/api.md §2 and §4) read algorithms
// and usages as names. encoding/json would send the proto enums as numbers,
// which the routes refuse with 400, so these codecs write the names instead.

// kmsKeyAlgorithmNames maps the proto key algorithm onto the names
// POST /api/v1/kms/keys accepts and returns. An algorithm absent here is one
// the route does not mint.
var kmsKeyAlgorithmNames = map[platformv1.KMSKeyAlgorithm]string{
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256:           "AES-256-GCM",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305: "CHACHA20-POLY1305",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048:          "RSA-2048",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096:          "RSA-4096",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256:        "ECDSA-P256",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384:        "ECDSA-P384",
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519:           "ED25519",
}

// kmsKeyAlgorithmsByName is kmsKeyAlgorithmNames inverted, for replies.
var kmsKeyAlgorithmsByName = invertKMSKeyAlgorithmNames()

// kmsKeyUsageNames maps the proto key usage onto the names
// POST /api/v1/kms/keys accepts.
var kmsKeyUsageNames = map[platformv1.KeyUsage]string{
	platformv1.KeyUsage_KEY_USAGE_ENCRYPT: "ENCRYPT",
	platformv1.KeyUsage_KEY_USAGE_DECRYPT: "DECRYPT",
	platformv1.KeyUsage_KEY_USAGE_SIGN:    "SIGN",
	platformv1.KeyUsage_KEY_USAGE_VERIFY:  "VERIFY",
	platformv1.KeyUsage_KEY_USAGE_WRAP:    "WRAP",
	platformv1.KeyUsage_KEY_USAGE_UNWRAP:  "UNWRAP",
}

// kmsGeneratedKeyReply is the reply shape of POST /api/v1/kms/keys.
type kmsGeneratedKeyReply struct {
	KeyID              string `json:"key_id"`
	Version            uint64 `json:"version"`
	Algorithm          string `json:"algorithm"`
	Exportable         bool   `json:"exportable"`
	DeletionProtection bool   `json:"deletion_protection"`
}

func init() {
	restRequestEncoders[platformv1.KeyManagementService_GenerateKey_FullMethodName] =
		requestEncoder(platformv1.KeyManagementService_GenerateKey_FullMethodName, encodeKMSGenerateKey)
	restRequestEncoders[platformv1.KeyManagementService_GenerateDataKey_FullMethodName] =
		requestEncoder(platformv1.KeyManagementService_GenerateDataKey_FullMethodName, encodeKMSGenerateDataKey)
	restRequestEncoders[platformv1.KeyManagementService_GenerateWrappedDataKey_FullMethodName] =
		requestEncoder(platformv1.KeyManagementService_GenerateWrappedDataKey_FullMethodName, encodeKMSGenerateWrappedDataKey)

	restResponseDecoders[platformv1.KeyManagementService_GenerateKey_FullMethodName] =
		wireDecoder(platformv1.KeyManagementService_GenerateKey_FullMethodName, decodeKMSGenerateKey)
}

// encodeKMSGenerateKey flattens the key spec onto the route's top-level
// fields, with the algorithm and usages as names.
func encodeKMSGenerateKey(req *platformv1.GenerateKeyRequest) (map[string]interface{}, error) {
	if req.GetDisplayName() != "" {
		return nil, ErrKeyDisplayNameNotSupported{KeyID: req.GetName()}
	}
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
	if req.GetDescription() != "" {
		body["description"] = req.GetDescription()
	}
	if len(req.GetTags()) > 0 {
		body["tags"] = req.GetTags()
	}
	if req.GetOwner() != "" {
		body["owner"] = req.GetOwner()
	}
	if spec.GetExportable() {
		body["exportable"] = true
	}
	if spec.GetDeletionProtection() {
		body["deletion_protection"] = true
	}
	return body, nil
}

// encodeKMSGenerateDataKey sends the algorithm as its proto name.
func encodeKMSGenerateDataKey(req *platformv1.GenerateDataKeyRequest) (map[string]interface{}, error) {
	body := map[string]interface{}{"key_id": req.GetKeyId()}
	if err := putKMSDataKeyShape(body, "algorithm", req.GetAlgorithm(), req.GetKeySize(), req.GetContext()); err != nil {
		return nil, err
	}
	return body, nil
}

// encodeKMSGenerateWrappedDataKey sends the key algorithm as its proto name.
// The route takes no wrapping algorithm — the KEK's own applies — so a
// request naming one is refused rather than sent and silently ignored.
func encodeKMSGenerateWrappedDataKey(req *platformv1.GenerateWrappedDataKeyRequest) (map[string]interface{}, error) {
	if alg := req.GetWrappingAlgorithm(); alg != platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_UNSPECIFIED {
		return nil, ErrWrappingAlgorithmNotSupported{Algorithm: alg.String()}
	}
	body := map[string]interface{}{"wrapping_key_id": req.GetWrappingKeyId()}
	if err := putKMSDataKeyShape(body, "key_algorithm", req.GetKeyAlgorithm(), req.GetKeySize(), req.GetContext()); err != nil {
		return nil, err
	}
	return body, nil
}

// putKMSDataKeyShape writes the fields the two data-key routes share. An
// unspecified algorithm is omitted so the size picks it; a value outside the
// proto enum has no name to send and is refused.
func putKMSDataKeyShape(body map[string]interface{}, algorithmField string, alg platformv1.KMSKeyAlgorithm, keySize int32, keyContext []byte) error {
	if alg != platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED {
		name, ok := platformv1.KMSKeyAlgorithm_name[int32(alg)]
		if !ok {
			return ErrKeyAlgorithmNotSupported{Algorithm: alg.String()}
		}
		body[algorithmField] = name
	}
	if keySize != 0 {
		body["key_size"] = keySize
	}
	if len(keyContext) > 0 {
		body["context"] = keyContext
	}
	return nil
}

// decodeKMSGenerateKey reads the route's flat reply into the key handle and
// metadata. An algorithm name the SDK does not know decodes as UNSPECIFIED.
func decodeKMSGenerateKey(raw []byte) (*platformv1.GenerateKeyResponse, error) {
	var reply kmsGeneratedKeyReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return &platformv1.GenerateKeyResponse{
		Status: &platformv1.Status{Success: true},
		Key: &platformv1.KMSKeyHandle{
			KeyId:     reply.KeyID,
			Version:   reply.Version,
			Algorithm: kmsKeyAlgorithmsByName[reply.Algorithm],
		},
		Metadata: &platformv1.KMSKeyMetadata{
			KeyId:              reply.KeyID,
			Algorithm:          kmsKeyAlgorithmsByName[reply.Algorithm],
			Version:            reply.Version,
			Exportable:         reply.Exportable,
			DeletionProtection: reply.DeletionProtection,
		},
	}, nil
}

func invertKMSKeyAlgorithmNames() map[string]platformv1.KMSKeyAlgorithm {
	byName := make(map[string]platformv1.KMSKeyAlgorithm, len(kmsKeyAlgorithmNames))
	for alg, name := range kmsKeyAlgorithmNames {
		byName[name] = alg
	}
	return byName
}
