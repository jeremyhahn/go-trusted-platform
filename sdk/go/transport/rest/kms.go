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

// The KMS crypto routes (docs/kms/api.md §3) carry the key name in the path
// and use their own body names: the signed bytes are "data", the hash is a
// name such as "SHA-256", and the key version is "version". The codecs below
// translate between those names and the proto messages.

// kmsHashNames maps the proto hash enum onto the names the REST routes accept.
// UNSPECIFIED is absent on purpose: the hash is then omitted and the server
// default (SHA-256) applies.
var kmsHashNames = map[platformv1.HashAlgorithm]string{
	platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256: "SHA-256",
	platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384: "SHA-384",
	platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512: "SHA-512",
}

// kmsVersionedReply is the reply shape Encrypt and Sign share on the wire.
type kmsVersionedReply struct {
	KeyID      string `json:"key_id"`
	Version    uint64 `json:"version"`
	Ciphertext []byte `json:"ciphertext"`
	Signature  []byte `json:"signature"`
}

func init() {
	restRequestEncoders[platformv1.KeyManagementService_Decrypt_FullMethodName] =
		requestEncoder(platformv1.KeyManagementService_Decrypt_FullMethodName, encodeKMSDecrypt)
	restRequestEncoders[platformv1.KeyManagementService_Sign_FullMethodName] =
		requestEncoder(platformv1.KeyManagementService_Sign_FullMethodName, encodeKMSSign)
	restRequestEncoders[platformv1.KeyManagementService_Verify_FullMethodName] =
		requestEncoder(platformv1.KeyManagementService_Verify_FullMethodName, encodeKMSVerify)

	restResponseDecoders[platformv1.KeyManagementService_Encrypt_FullMethodName] =
		wireDecoder(platformv1.KeyManagementService_Encrypt_FullMethodName, decodeKMSEncrypt)
	restResponseDecoders[platformv1.KeyManagementService_Sign_FullMethodName] =
		wireDecoder(platformv1.KeyManagementService_Sign_FullMethodName, decodeKMSSign)
}

// encodeKMSDecrypt sends the key version under the route's "version" name.
func encodeKMSDecrypt(req *platformv1.DecryptRequest) (map[string]interface{}, error) {
	body := map[string]interface{}{"ciphertext": req.GetCiphertext()}
	if len(req.GetContext()) > 0 {
		body["context"] = req.GetContext()
	}
	if req.GetKeyVersion() > 0 {
		body["version"] = req.GetKeyVersion()
	}
	return body, nil
}

// encodeKMSSign sends the message as "data" and the hash by name.
func encodeKMSSign(req *platformv1.SignRequest) (map[string]interface{}, error) {
	body := map[string]interface{}{"data": req.GetMessage()}
	if err := putKMSHash(body, req.GetHashAlgorithm()); err != nil {
		return nil, err
	}
	if req.GetPreHashed() {
		body["pre_hashed"] = true
	}
	return body, nil
}

// encodeKMSVerify sends the message as "data", the hash by name and the key
// version as "version".
func encodeKMSVerify(req *platformv1.VerifyRequest) (map[string]interface{}, error) {
	body := map[string]interface{}{
		"data":      req.GetMessage(),
		"signature": req.GetSignature(),
	}
	if err := putKMSHash(body, req.GetHashAlgorithm()); err != nil {
		return nil, err
	}
	if req.GetKeyVersion() > 0 {
		body["version"] = req.GetKeyVersion()
	}
	return body, nil
}

// putKMSHash adds the hash name to body. An unspecified hash is left out; a
// hash the routes cannot carry is refused rather than silently signed as
// SHA-256.
func putKMSHash(body map[string]interface{}, alg platformv1.HashAlgorithm) error {
	if alg == platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		return nil
	}
	name, ok := kmsHashNames[alg]
	if !ok {
		return ErrHashAlgorithmNotSupported{Algorithm: alg.String()}
	}
	body["hash"] = name
	return nil
}

// decodeKMSEncrypt reads the route's "version" into key_version.
func decodeKMSEncrypt(raw []byte) (*platformv1.EncryptResponse, error) {
	reply, err := unmarshalKMSVersionedReply(raw)
	if err != nil {
		return nil, err
	}
	return &platformv1.EncryptResponse{
		Status:     &platformv1.Status{Success: true},
		KeyId:      reply.KeyID,
		KeyVersion: reply.Version,
		Ciphertext: reply.Ciphertext,
	}, nil
}

// decodeKMSSign reads the route's "version" into key_version.
func decodeKMSSign(raw []byte) (*platformv1.SignResponse, error) {
	reply, err := unmarshalKMSVersionedReply(raw)
	if err != nil {
		return nil, err
	}
	return &platformv1.SignResponse{
		Status:     &platformv1.Status{Success: true},
		KeyId:      reply.KeyID,
		KeyVersion: reply.Version,
		Signature:  reply.Signature,
	}, nil
}

func unmarshalKMSVersionedReply(raw []byte) (kmsVersionedReply, error) {
	var reply kmsVersionedReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return reply, ErrUnmarshalFailed{Err: err}
	}
	return reply, nil
}
