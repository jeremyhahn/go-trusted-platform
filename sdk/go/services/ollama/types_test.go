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

package ollama

import (
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/ollama"
)

// TestTypes_AreUpstreamAliases proves every re-exported type IS the upstream
// type, so a value crosses the boundary without conversion. A defined type
// in place of an alias would be a distinct reflect.Type.
func TestTypes_AreUpstreamAliases(t *testing.T) {
	cases := []struct {
		name     string
		got      reflect.Type
		upstream reflect.Type
	}{
		{"Client", reflect.TypeFor[Client](), reflect.TypeFor[upstream.Client]()},
		{"ModelInfo", reflect.TypeFor[ModelInfo](), reflect.TypeFor[upstream.ModelInfo]()},
		{"ModelDetails", reflect.TypeFor[ModelDetails](), reflect.TypeFor[upstream.ModelDetails]()},
		{"EmbedRequest", reflect.TypeFor[EmbedRequest](), reflect.TypeFor[upstream.EmbedRequest]()},
		{"EmbedResponse", reflect.TypeFor[EmbedResponse](), reflect.TypeFor[upstream.EmbedResponse]()},
		{"EmbedWithModelRequest", reflect.TypeFor[EmbedWithModelRequest](), reflect.TypeFor[upstream.EmbedWithModelRequest]()},
		{"EmbedBatchRequest", reflect.TypeFor[EmbedBatchRequest](), reflect.TypeFor[upstream.EmbedBatchRequest]()},
		{"EmbedBatchResponse", reflect.TypeFor[EmbedBatchResponse](), reflect.TypeFor[upstream.EmbedBatchResponse]()},
		{"ListModelsRequest", reflect.TypeFor[ListModelsRequest](), reflect.TypeFor[upstream.ListModelsRequest]()},
		{"ListModelsResponse", reflect.TypeFor[ListModelsResponse](), reflect.TypeFor[upstream.ListModelsResponse]()},
		{"GetModelInfoRequest", reflect.TypeFor[GetModelInfoRequest](), reflect.TypeFor[upstream.GetModelInfoRequest]()},
		{"GetModelInfoResponse", reflect.TypeFor[GetModelInfoResponse](), reflect.TypeFor[upstream.GetModelInfoResponse]()},
		{"HealthRequest", reflect.TypeFor[HealthRequest](), reflect.TypeFor[upstream.HealthRequest]()},
		{"HealthResponse", reflect.TypeFor[HealthResponse](), reflect.TypeFor[upstream.HealthResponse]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}
