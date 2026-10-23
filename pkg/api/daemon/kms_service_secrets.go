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

package daemon

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
)

const (
	// secretRawKey is the SDK data-map key the adapter stores the opaque
	// secret bytes under.
	secretRawKey = "_raw"

	// secretServiceDataKey is the SDK data-map key the embedded transport
	// answers a quicbaas-secrets-service secret's bytes under.
	secretServiceDataKey = "data"

	// secretPrefixDataKey names the secret bytes in a GetSecretsByPrefix
	// SecretData.Data map.
	secretPrefixDataKey = "data"
)

// ErrSecretRawData reports a stored secret whose raw payload is neither
// bytes nor a base64 string, so the adapter cannot return its data.
type ErrSecretRawData struct {
	SecretID string
	Type     string
}

func (e ErrSecretRawData) Error() string {
	return fmt.Sprintf("secret %q: raw data has unsupported type %s", e.SecretID, e.Type)
}

// GRPCStatus maps the error to codes.DataLoss: the secret exists but its
// payload cannot be decoded.
func (e ErrSecretRawData) GRPCStatus() *status.Status {
	return status.New(codes.DataLoss, e.Error())
}

// secretRawData extracts the secret bytes StoreSecret wrote under
// secretRawKey. The SDK keeps them as []byte in memory, but a transport
// that JSON-encodes the data map (the embedded transport does) returns them
// as a base64 string. A secret the quicbaas secrets service wrote (the MCP
// secret_store and secret_rotate tools) has no secretRawKey: the embedded
// transport answers its bytes, when they are not a JSON object, as a plain
// string under secretServiceDataKey. A secret with neither key carries no
// raw payload.
func secretRawData(secretID string, data map[string]interface{}) ([]byte, error) {
	raw, ok := data[secretRawKey]
	if !ok || raw == nil {
		return secretServiceData(secretID, data)
	}
	switch v := raw.(type) {
	case []byte:
		return v, nil
	case string:
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, ErrSecretRawData{SecretID: secretID, Type: "non-base64 string"}
		}
		return decoded, nil
	default:
		return nil, ErrSecretRawData{SecretID: secretID, Type: fmt.Sprintf("%T", raw)}
	}
}

// secretServiceData extracts the bytes of a secret the quicbaas secrets
// service wrote: the embedded transport's handleSecretsGet puts bytes that
// do not decode as a JSON object under secretServiceDataKey as a string.
func secretServiceData(secretID string, data map[string]interface{}) ([]byte, error) {
	value, ok := data[secretServiceDataKey]
	if !ok || value == nil {
		return nil, nil
	}
	text, isString := value.(string)
	if !isString {
		return nil, ErrSecretRawData{SecretID: secretID, Type: fmt.Sprintf("%T", value)}
	}
	return []byte(text), nil
}

// listSecretPaths returns the sorted secret paths under prefix so offset
// cursors page through a stable order.
func (a *SecretsServerAdapter) listSecretPaths(ctx context.Context, prefix string) ([]string, error) {
	resp, err := a.client.List(ctx, prefix)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list secrets failed: %v", err)
	}
	paths := append([]string(nil), resp.Paths...)
	sort.Strings(paths)
	return paths, nil
}

// GetSecretsByPrefix returns the secrets whose path starts with the prefix,
// one page at a time, with their data when IncludeData is set.
func (a *SecretsServerAdapter) GetSecretsByPrefix(ctx context.Context, req *pb.GetSecretsByPrefixRequest) (*pb.GetSecretsByPrefixResponse, error) {
	if a.client == nil {
		return nil, status.Error(codes.Unavailable, "Secrets service unavailable")
	}

	paths, err := a.listSecretPaths(ctx, req.GetPrefix())
	if err != nil {
		return nil, err
	}
	start, end, nextCursor, hasMore, err := paginateKMSOffset(len(paths), req.GetLimit(), req.GetCursor())
	if err != nil {
		return nil, err
	}

	secrets := make(map[string]*pb.SecretData, end-start)
	for _, path := range paths[start:end] {
		entry := &pb.SecretData{}
		if req.GetIncludeData() {
			secret, getErr := a.client.Get(ctx, path)
			if getErr != nil {
				return nil, status.Errorf(codes.Internal, "get secret %q failed: %v", path, getErr)
			}
			raw, rawErr := secretRawData(path, secret.Data)
			if rawErr != nil {
				return nil, rawErr
			}
			entry.Data = map[string][]byte{secretPrefixDataKey: raw}
			entry.Metadata = secret.Metadata
			entry.Version = int64(secret.Version)
		}
		secrets[path] = entry
	}

	return &pb.GetSecretsByPrefixResponse{
		Secrets:    secrets,
		NextCursor: nextCursor,
		HasMore:    hasMore,
		TotalCount: int32(len(paths)),
		Timestamp:  time.Now().Unix(),
	}, nil
}
