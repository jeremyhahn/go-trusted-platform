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

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Attestation manifest build and verify (#452, #1968). The webservice and
// the daemon serve them at POST /attestation/manifests/build (answering 201)
// and POST /attestation/manifests/verify. Both handlers decode the body with
// protojson, which refuses the {seconds, nanos} shape encoding/json gives a
// google.protobuf.Timestamp, so both bodies are encoded as protojson here.
// The replies are protojson and decode generically.
func init() {
	grpcMethodToRESTMap[platformv1.AttestationService_BuildManifest_FullMethodName] = struct {
		path   string
		method string
	}{"/api/v1/attestation/manifests/build", http.MethodPost}
	grpcMethodToRESTMap[platformv1.AttestationService_VerifyManifest_FullMethodName] = struct {
		path   string
		method string
	}{"/api/v1/attestation/manifests/verify", http.MethodPost}

	restRequestEncoders[platformv1.AttestationService_BuildManifest_FullMethodName] =
		manifestProtoJSONEncoder[platformv1.BuildManifestRequest](platformv1.AttestationService_BuildManifest_FullMethodName)
	restRequestEncoders[platformv1.AttestationService_VerifyManifest_FullMethodName] =
		manifestProtoJSONEncoder[platformv1.VerifyManifestRequest](platformv1.AttestationService_VerifyManifest_FullMethodName)
}

// manifestRequestJSON writes proto field names, as the handlers' protojson
// decoder and the server's own replies use.
var manifestRequestJSON = protojson.MarshalOptions{UseProtoNames: true}

// manifestProtoJSONEncoder encodes the method's pb request as protojson and
// hands it to the adapter as raw JSON, so encoding/json sends it unchanged.
func manifestProtoJSONEncoder[P any, PT interface {
	*P
	proto.Message
}](method string) restRequestEncoder {
	return func(body interface{}) (interface{}, error) {
		req, ok := body.(PT)
		if !ok || req == nil {
			return nil, ErrUnexpectedRequestType{Method: method}
		}
		encoded, err := manifestRequestJSON.Marshal(req)
		if err != nil {
			return nil, ErrMarshalFailed{Err: err}
		}
		return json.RawMessage(encoded), nil
	}
}
