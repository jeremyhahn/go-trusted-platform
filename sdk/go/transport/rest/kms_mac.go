// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Commercial

package rest

import (
	"encoding/base64"
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
//
// Hash is served by both servers with different shapes: the webservice
// (types.go) reads {data, hash name} and replies {hash name, digest}; the
// daemon (pkg/api/rest/kms_handlers.go) reads {data, algorithm number} and
// replies {algorithm, hash (base64 digest), timestamp}. The body carries both
// names and the decoder reads either reply. HMAC and VerifyHMAC replies do not
// echo the hash or the key; restReplyCompleters take them from the request.
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

	restReplyCompleters[platformv1.KeyManagementService_HMAC_FullMethodName] = completeKMSHMAC
	restReplyCompleters[platformv1.KeyManagementService_VerifyHMAC_FullMethodName] = completeKMSVerifyHMAC
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

// encodeKMSHash reshapes a HashRequest into the {data, hash, algorithm}
// body: hash is the webservice's algorithm name, algorithm the daemon's
// proto enum number. Each server ignores the other's field.
func encodeKMSHash(req *platformv1.HashRequest) (map[string]interface{}, error) {
	body := map[string]interface{}{"data": req.GetData()}
	if err := putKMSHash(body, req.GetAlgorithm()); err != nil {
		return nil, err
	}
	if alg := req.GetAlgorithm(); alg != platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		body["algorithm"] = int32(alg)
	}
	return body, nil
}

// completeKMSHMAC sets the reply's hash_algorithm to the requested one, or
// SHA-256 (the server default) when the request leaves it unspecified.
func completeKMSHMAC(args, reply interface{}) {
	req, ok := args.(*platformv1.HMACRequest)
	resp, ok2 := reply.(*platformv1.HMACResponse)
	if !ok || !ok2 {
		return
	}
	alg := req.GetHashAlgorithm()
	if alg == platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		alg = platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256
	}
	resp.HashAlgorithm = alg
}

// completeKMSVerifyHMAC sets the reply's key_id to the verified key the
// request named, for either verdict.
func completeKMSVerifyHMAC(args, reply interface{}) {
	req, ok := args.(*platformv1.VerifyHMACRequest)
	resp, ok2 := reply.(*platformv1.VerifyHMACResponse)
	if !ok || !ok2 {
		return
	}
	resp.KeyId = req.GetKeyId()
}

// decodeKMSHMAC reads the route's {key_id, hmac} reply. The route does not
// echo the hash; completeKMSHMAC takes it from the request.
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

// decodeKMSHash reads either server's reply. The webservice's {hash, digest}
// names the hash the way kmsHashNames sends it; a name it does not know is a
// decode failure. The daemon's {algorithm, hash, timestamp} carries the proto
// enum number and the base64 digest in hash.
func decodeKMSHash(raw []byte) (*platformv1.HashResponse, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	var reply struct {
		Hash      string `json:"hash"`
		Digest    []byte `json:"digest"`
		Algorithm *int32 `json:"algorithm"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	if _, webservice := probe["digest"]; webservice {
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
	if reply.Algorithm == nil {
		return nil, ErrUnmarshalFailed{Err: fmt.Errorf("the KMS hash reply carries neither digest nor algorithm")}
	}
	digest, err := base64.StdEncoding.DecodeString(reply.Hash)
	if err != nil {
		return nil, ErrUnmarshalFailed{Err: fmt.Errorf("the daemon KMS hash reply digest: %w", err)}
	}
	return &platformv1.HashResponse{
		Status:    &platformv1.Status{Success: true},
		Algorithm: platformv1.HashAlgorithm(*reply.Algorithm),
		Hash:      digest,
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
