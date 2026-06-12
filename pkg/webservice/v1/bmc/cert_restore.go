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

package bmc

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	bmcpkg "github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// =============================================================================
// Restore types
// =============================================================================

// RestoreResult is the outcome of a successful factory-certificate restore
// ceremony, expressed in terms local to this package so BMCRestorerServicer
// carries no dependency on pkg/app.
type RestoreResult struct {
	DeviceID    uint64          `json:"device_id,string"`
	Endpoint    string          `json:"endpoint"`
	Hostname    string          `json:"hostname"`
	NewCertMeta FactoryCertMeta `json:"new_cert_meta"`
	NewCertPEM  []byte          `json:"-"`
	Steps       []EnrollStep    `json:"steps"`
}

// RestoreResponse is the JSON body returned by a successful restore ceremony.
// DeviceID is serialized as a string to preserve uint64 precision across
// JavaScript JSON parsers (which lose precision beyond 2^53).
type RestoreResponse struct {
	DeviceID    uint64                  `json:"device_id,string"`
	Endpoint    string                  `json:"endpoint"`
	Hostname    string                  `json:"hostname"`
	NewCertMeta FactoryCertMetaResponse `json:"new_cert_meta"`
	NewCertPEM  string                  `json:"new_cert_pem,omitempty"`
	Steps       []EnrollStepResponse    `json:"steps"`
}

// =============================================================================
// Restorer interface and handler extension
// =============================================================================

// BMCRestorerServicer is the narrow interface required by the REST handler to
// perform a BMC factory-certificate restore. It is satisfied by a daemon-side
// adapter that wraps *app.App so this package carries no import cycle.
type BMCRestorerServicer interface {
	// RestoreBMC runs the factory-certificate restore ceremony for deviceID / bmcCfg.
	RestoreBMC(ctx context.Context, deviceID uint64, bmcCfg *bmcpkg.Config) (*RestoreResult, error)

	// BMCTLSProvider returns the class-BMC TLS provider backed by the platform
	// trust resolver. Returns nil when no resolver is available.
	BMCTLSProvider() bmcpkg.TLSProvider
}

// restoreDeps holds the restorer and profile-lookup adapter injected after
// handler construction via SetRestorer.
type restoreDeps struct {
	restorer      BMCRestorerServicer
	profileLookup ProfileLookup
}

// SetRestorer injects the restorer and profile lookup after construction.
// The daemon calls this once the App and DeviceProfileService are available.
func (h *handler) SetRestorer(restorer BMCRestorerServicer, lookup ProfileLookup) {
	h.restoreDeps = restoreDeps{
		restorer:      restorer,
		profileLookup: lookup,
	}
}

// ErrBMCRestorerNotAvailable indicates the BMC restorer is not wired into
// the REST handler.
type ErrBMCRestorerNotAvailable struct{}

// Error returns the error message.
func (ErrBMCRestorerNotAvailable) Error() string {
	return "bmc: restorer not available (daemon started without App)"
}

// =============================================================================
// Handler method
// =============================================================================

// RestoreBMC runs the BMC factory-certificate restore ceremony for the device profile.
// POST /api/v1/bmc/{profileID}/cert/restore
func (h *handler) RestoreBMC(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: restore request received")

	if h.restoreDeps.restorer == nil {
		h.responseWriter.Error500(w, r, ErrBMCRestorerNotAvailable{})
		return
	}

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	var tlsProvider bmcpkg.TLSProvider
	if h.restoreDeps.restorer != nil {
		tlsProvider = h.restoreDeps.restorer.BMCTLSProvider()
	}

	bmcCfg, err := h.restoreDeps.profileLookup.BMCConfig(r.Context(), profileID, tlsProvider)
	if err != nil {
		h.writeBMCError(w, r, profileID, "restore_bmc lookup", err)
		return
	}

	result, err := h.restoreDeps.restorer.RestoreBMC(r.Context(), profileID, bmcCfg)
	if err != nil {
		h.writeBMCError(w, r, profileID, "restore_bmc", err)
		return
	}

	h.logger.Info("bmc: restore ceremony completed",
		slog.Uint64("profile_id", profileID),
		slog.Uint64("device_id", result.DeviceID))

	h.responseWriter.Success200(w, r, restoreResultToJSON(result))
}

// restoreResultToJSON converts a RestoreResult to the REST response shape.
func restoreResultToJSON(r *RestoreResult) *RestoreResponse {
	if r == nil {
		return &RestoreResponse{}
	}
	resp := &RestoreResponse{
		DeviceID: r.DeviceID,
		Endpoint: r.Endpoint,
		Hostname: r.Hostname,
		NewCertMeta: FactoryCertMetaResponse{
			Subject:      r.NewCertMeta.Subject,
			Issuer:       r.NewCertMeta.Issuer,
			SerialNumber: r.NewCertMeta.SerialNumber,
			NotBefore:    r.NewCertMeta.NotBefore,
			NotAfter:     r.NewCertMeta.NotAfter,
			SPKISHA256:   r.NewCertMeta.SPKISHA256,
			SHA256:       r.NewCertMeta.SHA256,
			CapturedAt:   r.NewCertMeta.CapturedAt,
		},
	}
	if len(r.NewCertPEM) > 0 {
		resp.NewCertPEM = string(r.NewCertPEM)
	}
	resp.Steps = make([]EnrollStepResponse, len(r.Steps))
	for i, s := range r.Steps {
		resp.Steps[i] = EnrollStepResponse{
			Name:   s.Name,
			OK:     s.OK,
			Detail: s.Detail,
		}
	}
	return resp
}

// FactoryCertMetaZero is a helper used in tests to produce a zeroed FactoryCertMeta.
func FactoryCertMetaZero() FactoryCertMeta {
	return FactoryCertMeta{
		NotBefore:  time.Time{},
		NotAfter:   time.Time{},
		CapturedAt: time.Time{},
	}
}
