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

package parameterstore

import (
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/parameterstore"
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
		{"ParameterValue", reflect.TypeFor[ParameterValue](), reflect.TypeFor[upstream.ParameterValue]()},
		{"SetParameterResult", reflect.TypeFor[SetParameterResult](), reflect.TypeFor[upstream.SetParameterResult]()},
		{"DeleteParameterResult", reflect.TypeFor[DeleteParameterResult](), reflect.TypeFor[upstream.DeleteParameterResult]()},
		{"SetParameterRequest", reflect.TypeFor[SetParameterRequest](), reflect.TypeFor[upstream.SetParameterRequest]()},
		{"SetParameterResponse", reflect.TypeFor[SetParameterResponse](), reflect.TypeFor[upstream.SetParameterResponse]()},
		{"GetParameterRequest", reflect.TypeFor[GetParameterRequest](), reflect.TypeFor[upstream.GetParameterRequest]()},
		{"GetParameterResponse", reflect.TypeFor[GetParameterResponse](), reflect.TypeFor[upstream.GetParameterResponse]()},
		{"DeleteParameterRequest", reflect.TypeFor[DeleteParameterRequest](), reflect.TypeFor[upstream.DeleteParameterRequest]()},
		{"DeleteParameterResponse", reflect.TypeFor[DeleteParameterResponse](), reflect.TypeFor[upstream.DeleteParameterResponse]()},
		{"ListParametersRequest", reflect.TypeFor[ListParametersRequest](), reflect.TypeFor[upstream.ListParametersRequest]()},
		{"ListParametersResponse", reflect.TypeFor[ListParametersResponse](), reflect.TypeFor[upstream.ListParametersResponse]()},
		{"SetParametersRequest", reflect.TypeFor[SetParametersRequest](), reflect.TypeFor[upstream.SetParametersRequest]()},
		{"SetParametersResponse", reflect.TypeFor[SetParametersResponse](), reflect.TypeFor[upstream.SetParametersResponse]()},
		{"GetParametersRequest", reflect.TypeFor[GetParametersRequest](), reflect.TypeFor[upstream.GetParametersRequest]()},
		{"GetParametersResponse", reflect.TypeFor[GetParametersResponse](), reflect.TypeFor[upstream.GetParametersResponse]()},
		{"DeleteParametersRequest", reflect.TypeFor[DeleteParametersRequest](), reflect.TypeFor[upstream.DeleteParametersRequest]()},
		{"DeleteParametersResponse", reflect.TypeFor[DeleteParametersResponse](), reflect.TypeFor[upstream.DeleteParametersResponse]()},
		{"SearchByTagsRequest", reflect.TypeFor[SearchByTagsRequest](), reflect.TypeFor[upstream.SearchByTagsRequest]()},
		{"SearchByTagsResponse", reflect.TypeFor[SearchByTagsResponse](), reflect.TypeFor[upstream.SearchByTagsResponse]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}
