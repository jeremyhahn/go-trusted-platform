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
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	bmcpkg "github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// =============================================================================
// Enroll types
// =============================================================================

// EnrollRequest is the JSON body for POST /api/v1/bmc/{profileID}/enroll.
// All fields are optional; absent fields use the profile's enrollment config defaults.
type EnrollRequest struct {
	// ReplaceCertificate overrides the profile's replace_certificate enrollment flag.
	ReplaceCertificate *bool `json:"replace_certificate,omitempty"`
	// RotatePassword overrides the profile's rotate_password enrollment flag.
	RotatePassword *bool `json:"rotate_password,omitempty"`
	// DNSRegister overrides the profile's dns_register enrollment flag.
	DNSRegister *bool `json:"dns_register,omitempty"`
	// DANEPublish overrides the profile's dane_publish enrollment flag.
	DANEPublish *bool `json:"dane_publish,omitempty"`
}

// EnrollOptions carries optional per-enrollment overrides for use in the
// BMCEnrollerServicer interface. Nil pointer fields preserve the profile's
// stored enrollment config defaults.
type EnrollOptions struct {
	ReplaceCertificate *bool
	RotatePassword     *bool
	DNSRegister        *bool
	DANEPublish        *bool
}

// EnrollStep is the result of a single step in the enrollment ceremony.
type EnrollStep struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// FactoryCertMeta holds metadata about the BMC factory certificate captured
// at the start of the enrollment ceremony.
type FactoryCertMeta struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SPKISHA256   string    `json:"spki_sha256"`
	SHA256       string    `json:"sha256"`
	CapturedAt   time.Time `json:"captured_at"`
}

// EnrollResult is the outcome of a successful enrollment ceremony, expressed
// in terms local to this package so BMCEnrollerServicer carries no dependency
// on pkg/app.
type EnrollResult struct {
	DeviceID        uint64          `json:"device_id,string"`
	Endpoint        string          `json:"endpoint"`
	Hostname        string          `json:"hostname"`
	DNSName         string          `json:"dns_name,omitempty"`
	PinSPKISHA256   string          `json:"pin_spki_sha256"`
	FactoryCertPEM  []byte          `json:"-"`
	FactoryCertMeta FactoryCertMeta `json:"factory_cert_meta"`
	NewCertPEM      []byte          `json:"-"`
	CACertPEM       []byte          `json:"-"`
	Steps           []EnrollStep    `json:"steps"`
}

// EnrollStepResponse is the JSON output shape for a single enrollment step.
// It is intentionally flat so the response body is easy to consume.
type EnrollStepResponse struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// FactoryCertMetaResponse is the JSON output shape for factory cert metadata.
type FactoryCertMetaResponse struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SPKISHA256   string    `json:"spki_sha256"`
	SHA256       string    `json:"sha256"`
	CapturedAt   time.Time `json:"captured_at"`
}

// EnrollResponse is the JSON body returned by a successful enrollment ceremony.
// DeviceID is serialized as a string to preserve uint64 precision across
// JavaScript JSON parsers (which lose precision beyond 2^53).
type EnrollResponse struct {
	DeviceID        uint64                  `json:"device_id,string"`
	Endpoint        string                  `json:"endpoint"`
	Hostname        string                  `json:"hostname"`
	DNSName         string                  `json:"dns_name,omitempty"`
	PinSPKISHA256   string                  `json:"pin_spki_sha256"`
	FactoryCertPEM  string                  `json:"factory_cert_pem,omitempty"`
	FactoryCertMeta FactoryCertMetaResponse `json:"factory_cert_meta"`
	NewCertPEM      string                  `json:"new_cert_pem,omitempty"`
	CACertPEM       string                  `json:"ca_cert_pem,omitempty"`
	Steps           []EnrollStepResponse    `json:"steps"`
}

// =============================================================================
// Enroller interface and HandlerParams extension
// =============================================================================

// BMCEnrollerServicer is the narrow interface required by the REST handler to
// perform BMC enrollment. It is satisfied by a daemon-side adapter that wraps
// *app.App so this package carries no import cycle through pkg/app.
//
// EnrollBMC receives a *bmcpkg.Config (resolved by ProfileLookup) and an
// *EnrollOptions (populated from the JSON request body). It returns an
// *EnrollResult or an error.
type BMCEnrollerServicer interface {
	// EnrollBMC runs the enrollment ceremony for deviceID / bmcCfg.
	EnrollBMC(ctx context.Context, deviceID uint64, bmcCfg *bmcpkg.Config, opts *EnrollOptions) (*EnrollResult, error)

	// BMCTLSProvider returns the class-BMC TLS provider backed by the platform
	// trust resolver. Returns nil when no resolver is available.
	BMCTLSProvider() bmcpkg.TLSProvider
}

// ProfileLookup provides profile-based BMC config resolution for the REST
// handler. Satisfied by device.DeviceProfileService + profileBMCToConfig.
type ProfileLookup interface {
	// BMCConfig returns the *bmc.Config for the given profile ID. Returns
	// bmc.ErrProfileNotFound when the profile is absent or has no BMC config.
	BMCConfig(ctx context.Context, profileID uint64, tlsProvider bmcpkg.TLSProvider) (*bmcpkg.Config, error)
}

// =============================================================================
// Handler extension
// =============================================================================

// enrollDeps holds the enroller and profile-lookup adapter injected after
// handler construction via SetEnroller.
type enrollDeps struct {
	enroller      BMCEnrollerServicer
	profileLookup ProfileLookup
}

// SetEnroller injects the enroller and profile lookup after construction.
// The daemon calls this once the App and DeviceProfileService are available.
func (h *handler) SetEnroller(enroller BMCEnrollerServicer, lookup ProfileLookup) {
	h.enrollDeps = enrollDeps{
		enroller:      enroller,
		profileLookup: lookup,
	}
}

// EnrollBMC runs the BMC enrollment ceremony for the device profile.
// POST /api/v1/bmc/{profileID}/enroll
func (h *handler) EnrollBMC(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: enroll request received")

	if h.enrollDeps.enroller == nil {
		h.responseWriter.Error503(w, r, ErrBMCEnrollerNotAvailable{})
		return
	}

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	var req EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("bmc: failed to decode enroll request body",
			slog.String("error", err.Error()))
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	var tlsProvider bmcpkg.TLSProvider
	if h.enrollDeps.enroller != nil {
		tlsProvider = h.enrollDeps.enroller.BMCTLSProvider()
	}

	bmcCfg, err := h.enrollDeps.profileLookup.BMCConfig(r.Context(), profileID, tlsProvider)
	if err != nil {
		h.writeBMCError(w, r, profileID, "enroll_bmc lookup", err)
		return
	}

	opts := &EnrollOptions{
		ReplaceCertificate: req.ReplaceCertificate,
		RotatePassword:     req.RotatePassword,
		DNSRegister:        req.DNSRegister,
		DANEPublish:        req.DANEPublish,
	}

	result, err := h.enrollDeps.enroller.EnrollBMC(r.Context(), profileID, bmcCfg, opts)
	if err != nil {
		h.writeBMCError(w, r, profileID, "enroll_bmc", err)
		return
	}

	h.logger.Info("bmc: enrollment ceremony completed",
		slog.Uint64("profile_id", profileID),
		slog.Uint64("device_id", result.DeviceID))

	h.responseWriter.Success200(w, r, enrollResultToJSON(result))
}

// enrollResultToJSON converts an EnrollResult to the REST response shape.
func enrollResultToJSON(r *EnrollResult) *EnrollResponse {
	if r == nil {
		return &EnrollResponse{}
	}
	resp := &EnrollResponse{
		DeviceID:      r.DeviceID,
		Endpoint:      r.Endpoint,
		Hostname:      r.Hostname,
		DNSName:       r.DNSName,
		PinSPKISHA256: r.PinSPKISHA256,
		FactoryCertMeta: FactoryCertMetaResponse{
			Subject:      r.FactoryCertMeta.Subject,
			Issuer:       r.FactoryCertMeta.Issuer,
			SerialNumber: r.FactoryCertMeta.SerialNumber,
			NotBefore:    r.FactoryCertMeta.NotBefore,
			NotAfter:     r.FactoryCertMeta.NotAfter,
			SPKISHA256:   r.FactoryCertMeta.SPKISHA256,
			SHA256:       r.FactoryCertMeta.SHA256,
			CapturedAt:   r.FactoryCertMeta.CapturedAt,
		},
	}
	if len(r.FactoryCertPEM) > 0 {
		resp.FactoryCertPEM = string(r.FactoryCertPEM)
	}
	if len(r.NewCertPEM) > 0 {
		resp.NewCertPEM = string(r.NewCertPEM)
	}
	if len(r.CACertPEM) > 0 {
		resp.CACertPEM = string(r.CACertPEM)
	}
	resp.Steps = make([]EnrollStepResponse, len(r.Steps))
	for i, s := range r.Steps {
		resp.Steps[i] = EnrollStepResponse(s)
	}
	return resp
}

// ErrBMCEnrollerNotAvailable indicates the BMC enroller is not wired into
// the REST handler.
type ErrBMCEnrollerNotAvailable struct{}

// Error returns the error message.
func (ErrBMCEnrollerNotAvailable) Error() string {
	return "bmc: enroller not available (daemon started without App)"
}
