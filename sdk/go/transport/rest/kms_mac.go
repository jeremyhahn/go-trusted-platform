// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Commercial

package rest

import (
	"encoding/json"
	"fmt"
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The webservice KMS router (pkg/webservice/v1/rest/kms/router.go) serves
// HMAC and VerifyHMAC with the key in the path and Hash with no key. Their
// bodies carry the webservice wire names (types.go): data, hmac and hash.
// The server reads an unknown or empty hash name as SHA-256, so a hash the
// routes cannot carry is refused here by putKMSHash.
func init() {
	templatedRouteTable[platformv1.KeyManagementService_HMAC_FullMethodName] =
		itemRoute("/api/v1/kms/hmac/{name}", http.MethodPost, "{name}", "key_id")
	templatedRouteTable[platformv1.KeyManagementService_VerifyHMAC_FullMethodName] =
		itemRoute("/api/v1/kms/hmac/{name}/verify", http.MethodPost, "{name}", "key_id")
	templatedRouteTable[platformv1.KeyManagementService_Hash_FullMethodName] = templatedRoute{
		path:   "/api/v1/kms/hash",
		method: http.MethodPost,
	}

	restRequestEncoders[platformv1.KeyManagementService_HMAC_FullMethodName] =
		requestEncoder(platformv1.KeyManagementService_HMAC_FullMethodName, encodeKMSHMAC)
	restRequestEncoders[platformv1.KeyManagementService_VerifyHMAC_FullMethodName] =
		requestEncoder(platformv1.KeyManagementService_VerifyHMAC_FullMethodName, encodeKMSVerifyHMAC)
	restRequestEncoders[platformv1.KeyManagementService_Hash_FullMethodName] =
		requestEncoder(platformv1.KeyManagementService_Hash_FullMethodName, encodeKMSHash)

	restResponseDecoders[platformv1.KeyManagementService_HMAC_FullMethodName] =
		wireDecoder(platformv1.KeyManagementService_HMAC_FullMethodName, decodeKMSHMAC)
	restResponseDecoders[platformv1.KeyManagementService_VerifyHMAC_FullMethodName] =
		wireDecoder(platformv1.KeyManagementService_VerifyHMAC_FullMethodName, decodeKMSVerifyHMAC)
	restResponseDecoders[platformv1.KeyManagementService_Hash_FullMethodName] =
		wireDecoder(platformv1.KeyManagementService_Hash_FullMethodName, decodeKMSHash)
}

// encodeKMSHMAC reshapes an HMACRequest into the route's {data, hash} body.
func encodeKMSHMAC(req *platformv1.HMACRequest) (map[string]interface{}, error) {
	body := map[string]interface{}{"data": req.GetMessage()}
	if err := putKMSHash(body, req.GetHashAlgorithm()); err != nil {
		return nil, err
	}
	return body, nil
}

// encodeKMSVerifyHMAC reshapes a VerifyHMACRequest into {data, hmac, hash}.
// The route verifies against the current key and takes no version, so a
// pinned version is refused rather than silently dropped.
func encodeKMSVerifyHMAC(req *platformv1.VerifyHMACRequest) (map[string]interface{}, error) {
	if req.GetKeyVersion() != 0 {
		return nil, fmt.Errorf("key_version %d: the VerifyHMAC REST route verifies against the current key version only", req.GetKeyVersion())
	}
	body := map[string]interface{}{
		"data": req.GetMessage(),
		"hmac": req.GetHmac(),
	}
	if err := putKMSHash(body, req.GetHashAlgorithm()); err != nil {
		return nil, err
	}
	return body, nil
}

// encodeKMSHash reshapes a HashRequest into the route's {data, hash} body.
func encodeKMSHash(req *platformv1.HashRequest) (map[string]interface{}, error) {
	body := map[string]interface{}{"data": req.GetData()}
	if err := putKMSHash(body, req.GetAlgorithm()); err != nil {
		return nil, err
	}
	return body, nil
}

// decodeKMSHMAC reads the route's {key_id, hmac} reply. The route does not
// echo the hash, so hash_algorithm stays unset.
func decodeKMSHMAC(raw []byte) (*platformv1.HMACResponse, error) {
	var reply struct {
		KeyID string `json:"key_id"`
		HMAC  []byte `json:"hmac"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return &platformv1.HMACResponse{
		Status: &platformv1.Status{Success: true},
		KeyId:  reply.KeyID,
		Hmac:   reply.HMAC,
	}, nil
}

// decodeKMSVerifyHMAC reads the route's {valid} reply.
func decodeKMSVerifyHMAC(raw []byte) (*platformv1.VerifyHMACResponse, error) {
	var reply struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return &platformv1.VerifyHMACResponse{
		Status: &platformv1.Status{Success: true},
		Valid:  reply.Valid,
	}, nil
}

// decodeKMSHash reads the route's {hash, digest} reply. The hash name is the
// one kmsHashNames sends; a name it does not know is a decode failure.
func decodeKMSHash(raw []byte) (*platformv1.HashResponse, error) {
	var reply struct {
		Hash   string `json:"hash"`
		Digest []byte `json:"digest"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	alg, ok := kmsHashByName(reply.Hash)
	if !ok {
		return nil, ErrUnmarshalFailed{Err: fmt.Errorf("unknown hash algorithm %q in the KMS hash reply", reply.Hash)}
	}
	return &platformv1.HashResponse{
		Status:    &platformv1.Status{Success: true},
		Algorithm: alg,
		Hash:      reply.Digest,
	}, nil
}

// kmsHashByName inverts kmsHashNames.
func kmsHashByName(name string) (platformv1.HashAlgorithm, bool) {
	for alg, n := range kmsHashNames {
		if n == name {
			return alg, true
		}
	}
	return platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, false
}
