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
	"encoding/json"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// DecodeGetBundleJSON decodes the bare bundle that GET /vtpm/bundles/{id}
// replies with (webservice and daemon alike) into GetBundleResponse.
func DecodeGetBundleJSON(data []byte) (*platformv1.GetBundleResponse, error) {
	var probe struct {
		Manifest    json.RawMessage `json:"manifest"`
		Hostname    *string         `json:"hostname"`
		EKAlgorithm *string         `json:"ek_algorithm"`
	}
	if err := decodeJSON(data, "get bundle", &probe); err != nil {
		return nil, err
	}
	if probe.Manifest == nil && (probe.Hostname != nil || probe.EKAlgorithm != nil) {
		var d daemonBundleJSON
		if err := decodeJSON(data, "get bundle", &d); err != nil {
			return nil, err
		}
		bundle, err := d.toProto()
		if err != nil {
			return nil, err
		}
		return &platformv1.GetBundleResponse{Bundle: bundle}, nil
	}
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

// daemonBundleJSON is the daemon's GetBundle reply (BundleResponse in
// pkg/api/rest): the manifest fields sit at the top level and
// secure_boot_keys holds the key fingerprints, not key file paths.
type daemonBundleJSON struct {
	ID                string                 `json:"id"`
	Mode              string                 `json:"mode"`
	Hostname          string                 `json:"hostname"`
	EKAlgorithm       string                 `json:"ek_algorithm"`
	SecureBootEnabled bool                   `json:"secure_boot_enabled"`
	CreatedAt         *time.Time             `json:"created_at"`
	ClonedFrom        string                 `json:"cloned_from"`
	Labels            map[string]string      `json:"labels"`
	EKCertificate     *ekCertJSON            `json:"ek_certificate"`
	SecureBootKeys    *secureBootKeyInfoJSON `json:"secure_boot_keys"`
}

// toProto builds the Bundle with its Manifest from the flat daemon fields.
// The daemon leaves every manifest field empty when the bundle has no
// manifest; the Manifest then stays nil.
func (d *daemonBundleJSON) toProto() (*platformv1.Bundle, error) {
	w := bundleJSON{
		ID:         d.ID,
		Mode:       d.Mode,
		CreatedAt:  d.CreatedAt,
		ClonedFrom: d.ClonedFrom,
	}
	if d.Hostname != "" || d.EKAlgorithm != "" || d.SecureBootEnabled || len(d.Labels) > 0 ||
		d.EKCertificate != nil || d.SecureBootKeys != nil {
		w.Manifest = &manifestJSON{
			ID:                d.ID,
			Mode:              d.Mode,
			Hostname:          d.Hostname,
			CreatedAt:         d.CreatedAt,
			EKCertificate:     d.EKCertificate,
			EKAlgorithm:       d.EKAlgorithm,
			SecureBootEnabled: d.SecureBootEnabled,
			SecureBootKeys:    d.SecureBootKeys,
			Labels:            d.Labels,
			ClonedFrom:        d.ClonedFrom,
		}
	}
	return w.toProto()
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
