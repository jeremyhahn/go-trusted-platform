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
	"net/http"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Registry image delete (#452). The webservice serves it at
// DELETE /api/v1/compute/images/{repository:.+}
// (pkg/webservice/v1/rest/registry/router.go), where the last path segment
// is repo:tag. Without a row here the flat fallback sent
// POST /api/v1/registry/delete, which no server serves. An empty repository
// or reference is refused before the wire. force and digest stay in the
// body, which the handler does not read.
//
// The handler answers the Go grpcapi.RegistryDeleteResponse, which has no
// json tags: PascalCase keys and an RFC 3339 time, hence the decoder.
func init() {
	templatedRouteTable[platformv1.RegistryService_Delete_FullMethodName] = templatedRoute{
		path:   "/api/v1/compute/images/{repository}:{reference}",
		method: http.MethodDelete,
		pathParams: []pathParam{
			{placeholder: "{repository}", field: "repository"},
			{placeholder: "{reference}", field: "reference"},
		},
	}
	restResponseDecoders[platformv1.RegistryService_Delete_FullMethodName] =
		wireDecoder(platformv1.RegistryService_Delete_FullMethodName, decodeRegistryDelete)
}

// registryDeleteWire is the JSON of grpcapi.RegistryDeleteResponse.
type registryDeleteWire struct {
	Digest     string
	BytesFreed int64
	Timestamp  time.Time
}

// decodeRegistryDelete maps the served reply onto DeleteArtifactResponse.
func decodeRegistryDelete(raw []byte) (*platformv1.DeleteArtifactResponse, error) {
	var wire registryDeleteWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	out := &platformv1.DeleteArtifactResponse{
		Status:     &platformv1.Status{Success: true},
		Digest:     wire.Digest,
		BytesFreed: wire.BytesFreed,
	}
	if !wire.Timestamp.IsZero() {
		out.Timestamp = timestamppb.New(wire.Timestamp)
	}
	return out, nil
}
