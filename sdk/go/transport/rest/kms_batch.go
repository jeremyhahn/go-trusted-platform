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

package rest

import (
	"encoding/json"
	"strconv"

	"google.golang.org/protobuf/reflect/protoreflect"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Key export, the batch operations and rewrap are served by the daemon REST
// server (docs/kms/api.md §2 and §3). Batch requests already carry the proto
// field names; their replies report each item's failure as an "error" string
// rather than a Status. Rewrap names the source and destination keys apart,
// and the proto rewraps under one key, so both are the request's key.

// kmsExportReply is the reply shape of GET /api/v1/kms/keys/{id}/export.
type kmsExportReply struct {
	KeyID             string `json:"key_id"`
	Format            int32  `json:"format"`
	WrappingKeyID     string `json:"wrapping_key_id"`
	WrappingAlgorithm int32  `json:"wrapping_algorithm"`
	WrappedMaterial   []byte `json:"wrapped_material"`
	Version           uint64 `json:"version"`
	Timestamp         int64  `json:"timestamp"`
}

// kmsBatchItemReply is one result of the batch routes. key_version is set
// per item by batch-decrypt; batch-encrypt reports it once for the batch.
type kmsBatchItemReply struct {
	ItemID     string `json:"item_id"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	Plaintext  []byte `json:"plaintext"`
	KeyVersion uint64 `json:"key_version"`
	Error      string `json:"error"`
}

// kmsBatchReply is the reply shape the two batch routes share.
type kmsBatchReply struct {
	KeyID        string              `json:"key_id"`
	KeyVersion   uint64              `json:"key_version"`
	Results      []kmsBatchItemReply `json:"results"`
	SuccessCount int32               `json:"success_count"`
	FailureCount int32               `json:"failure_count"`
	Timestamp    int64               `json:"timestamp"`
}

// kmsRewrapReply is the reply shape of POST /api/v1/kms/rewrap.
type kmsRewrapReply struct {
	SourceKeyID      string `json:"source_key_id"`
	SourceKeyVersion uint64 `json:"source_key_version"`
	DestKeyVersion   uint64 `json:"dest_key_version"`
	Ciphertext       []byte `json:"ciphertext"`
	Nonce            []byte `json:"nonce"`
	Timestamp        int64  `json:"timestamp"`
}

func init() {
	restRequestEncoders[platformv1.KeyManagementService_Rewrap_FullMethodName] =
		requestEncoder(platformv1.KeyManagementService_Rewrap_FullMethodName, encodeKMSRewrap)

	restResponseDecoders[platformv1.KeyManagementService_ExportKey_FullMethodName] =
		wireDecoder(platformv1.KeyManagementService_ExportKey_FullMethodName, decodeKMSExportKey)
	restResponseDecoders[platformv1.KeyManagementService_BatchEncrypt_FullMethodName] =
		wireDecoder(platformv1.KeyManagementService_BatchEncrypt_FullMethodName, decodeKMSBatchEncrypt)
	restResponseDecoders[platformv1.KeyManagementService_BatchDecrypt_FullMethodName] =
		wireDecoder(platformv1.KeyManagementService_BatchDecrypt_FullMethodName, decodeKMSBatchDecrypt)
	restResponseDecoders[platformv1.KeyManagementService_Rewrap_FullMethodName] =
		wireDecoder(platformv1.KeyManagementService_Rewrap_FullMethodName, decodeKMSRewrap)
}

// encodeEnumNumber renders an enum query value as its number, for a route
// that parses integers. The zero value is unset and omitted.
func encodeEnumNumber(v protoreflect.Value) string {
	if v.Enum() == 0 {
		return ""
	}
	return strconv.FormatInt(int64(v.Enum()), 10)
}

// encodeKMSRewrap names the request's key as both source and destination.
// A source version is sent as asked; the server refuses one it cannot honour.
func encodeKMSRewrap(req *platformv1.RewrapRequest) (map[string]interface{}, error) {
	body := map[string]interface{}{
		"source_key_id":      req.GetKeyId(),
		"destination_key_id": req.GetKeyId(),
		"ciphertext":         req.GetCiphertext(),
	}
	if len(req.GetContext()) > 0 {
		body["source_context"] = req.GetContext()
	}
	if len(req.GetNonce()) > 0 {
		body["source_nonce"] = req.GetNonce()
	}
	if req.GetSourceVersion() > 0 {
		body["source_key_version"] = req.GetSourceVersion()
	}
	return body, nil
}

// decodeKMSExportKey reads the route's numeric enums into the proto enums.
func decodeKMSExportKey(raw []byte) (*platformv1.ExportKeyResponse, error) {
	var reply kmsExportReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return &platformv1.ExportKeyResponse{
		Status:            &platformv1.Status{Success: true},
		KeyId:             reply.KeyID,
		Format:            platformv1.KeyExportFormat(reply.Format),
		WrappingKeyId:     reply.WrappingKeyID,
		WrappingAlgorithm: platformv1.WrappingAlgorithm(reply.WrappingAlgorithm),
		WrappedMaterial:   reply.WrappedMaterial,
		Version:           reply.Version,
		Timestamp:         reply.Timestamp,
	}, nil
}

// decodeKMSBatchEncrypt gives every item a Status from its error, and each
// successful item the batch's key version.
func decodeKMSBatchEncrypt(raw []byte) (*platformv1.BatchEncryptResponse, error) {
	reply, err := unmarshalKMSBatchReply(raw)
	if err != nil {
		return nil, err
	}
	results := make([]*platformv1.BatchEncryptResultItem, len(reply.Results))
	for i, item := range reply.Results {
		result := &platformv1.BatchEncryptResultItem{
			ItemId:     item.ItemID,
			Status:     kmsBatchItemStatus(item),
			Ciphertext: item.Ciphertext,
			Nonce:      item.Nonce,
		}
		if item.Error == "" {
			result.KeyVersion = reply.KeyVersion
		}
		results[i] = result
	}
	return &platformv1.BatchEncryptResponse{
		Status:       &platformv1.Status{Success: true},
		KeyId:        reply.KeyID,
		Results:      results,
		SuccessCount: reply.SuccessCount,
		FailureCount: reply.FailureCount,
		Timestamp:    reply.Timestamp,
	}, nil
}

// decodeKMSBatchDecrypt gives every item a Status from its error.
func decodeKMSBatchDecrypt(raw []byte) (*platformv1.BatchDecryptResponse, error) {
	reply, err := unmarshalKMSBatchReply(raw)
	if err != nil {
		return nil, err
	}
	results := make([]*platformv1.BatchDecryptResultItem, len(reply.Results))
	for i, item := range reply.Results {
		results[i] = &platformv1.BatchDecryptResultItem{
			ItemId:     item.ItemID,
			Status:     kmsBatchItemStatus(item),
			Plaintext:  item.Plaintext,
			KeyVersion: item.KeyVersion,
		}
	}
	return &platformv1.BatchDecryptResponse{
		Status:       &platformv1.Status{Success: true},
		KeyId:        reply.KeyID,
		Results:      results,
		SuccessCount: reply.SuccessCount,
		FailureCount: reply.FailureCount,
		Timestamp:    reply.Timestamp,
	}, nil
}

// decodeKMSRewrap reads the source and destination versions into the
// proto's source and target versions.
func decodeKMSRewrap(raw []byte) (*platformv1.RewrapResponse, error) {
	var reply kmsRewrapReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return &platformv1.RewrapResponse{
		Status:        &platformv1.Status{Success: true},
		KeyId:         reply.SourceKeyID,
		SourceVersion: reply.SourceKeyVersion,
		TargetVersion: reply.DestKeyVersion,
		Ciphertext:    reply.Ciphertext,
		Nonce:         reply.Nonce,
		Timestamp:     reply.Timestamp,
	}, nil
}

func unmarshalKMSBatchReply(raw []byte) (kmsBatchReply, error) {
	var reply kmsBatchReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return reply, ErrUnmarshalFailed{Err: err}
	}
	return reply, nil
}

// kmsBatchItemStatus reports an item as failed exactly when the route gave
// it an error.
func kmsBatchItemStatus(item kmsBatchItemReply) *platformv1.Status {
	if item.Error != "" {
		return &platformv1.Status{Success: false, Message: item.Error}
	}
	return &platformv1.Status{Success: true}
}
