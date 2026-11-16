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

package vtpm

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// DecodeGetBundleJSON decodes the bare bundle that GET /vtpm/bundles/{id}
// replies with (webservice and daemon alike) into GetBundleResponse.
func DecodeGetBundleJSON(data []byte) (*platformv1.GetBundleResponse, error) {
	var w bundleJSON
	if err := decodeJSON(data, "get bundle", &w); err != nil {
		return nil, err
	}
	bundle, err := w.toProto()
	if err != nil {
		return nil, err
	}
	return &platformv1.GetBundleResponse{Bundle: bundle}, nil
}

// DecodeValidateBundleJSON decodes the {valid, errors} reply of
// POST /vtpm/bundles/{id}/validate. The servers answer 200 for an invalid
// bundle too, so the call succeeds and Valid carries the verdict; the
// daemon's extra timestamp field is ignored.
func DecodeValidateBundleJSON(data []byte) (*platformv1.ValidateBundleResponse, error) {
	var w struct {
		Valid  bool     `json:"valid"`
		Errors []string `json:"errors"`
	}
	if err := decodeJSON(data, "validate bundle", &w); err != nil {
		return nil, err
	}
	return &platformv1.ValidateBundleResponse{
		Status: &platformv1.Status{Success: true, Message: "bundle validated"},
		Valid:  w.Valid,
		Errors: w.Errors,
	}, nil
}
