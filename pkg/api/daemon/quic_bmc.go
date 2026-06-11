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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
)

// =============================================================================
// QUIC BMC enrollment handler
// =============================================================================
//
// OpBMCCategory (0x9F) follows the category-opcode pattern used by Phase 3.5
// services: the first payload byte is the sub-opcode that selects the
// operation, the remaining bytes carry the MessagePack-encoded sub-request.
//
// Only one sub-opcode is defined currently:
//
//	BMCSubEnroll (0x01) – BMC enrollment ceremony

// bmcEnrollQUICHandlers holds the BMCEnroller and DeviceProfileService
// needed to drive the enrollment ceremony over QUIC. The enroller and
// profileSvc are set via QUICServiceHandler.SetBMCEnroller.
type bmcEnrollQUICHandlers struct {
	enroller   BMCEnroller
	profileSvc device.DeviceProfileService
}

// =============================================================================
// QUIC wire types (MessagePack codec tags)
// =============================================================================

// QUICBMCEnrollRequest is the MessagePack wire format for the BMC enrollment
// sub-request. Optional boolean fields use *bool for presence semantics so
// the profile defaults are preserved when the caller omits a flag.
type QUICBMCEnrollRequest struct {
	ProfileID          uint64 `codec:"profile_id"`
	ReplaceCertificate *bool  `codec:"replace_certificate,omitempty"`
	RotatePassword     *bool  `codec:"rotate_password,omitempty"`
	DNSRegister        *bool  `codec:"dns_register,omitempty"`
	DANEPublish        *bool  `codec:"dane_publish,omitempty"`
}

// QUICBMCEnrollStepResponse is the MessagePack wire format for a single
// enrollment step result.
type QUICBMCEnrollStepResponse struct {
	Name   string `codec:"name"`
	OK     bool   `codec:"ok"`
	Detail string `codec:"detail,omitempty"`
}

// QUICBMCFactoryCertMetaResponse is the MessagePack wire format for the
// factory certificate metadata captured during enrollment.
type QUICBMCFactoryCertMetaResponse struct {
	Subject      string `codec:"subject"`
	Issuer       string `codec:"issuer"`
	SerialNumber string `codec:"serial_number"`
	NotBefore    int64  `codec:"not_before"`
	NotAfter     int64  `codec:"not_after"`
	SPKISHA256   string `codec:"spki_sha256"`
	SHA256       string `codec:"sha256"`
	CapturedAt   int64  `codec:"captured_at"`
}

// QUICBMCEnrollResponse is the MessagePack wire format for a successful BMC
// enrollment ceremony result. DeviceID uses uint64 directly — MessagePack
// preserves full integer precision so there is no JS-truncation concern here.
type QUICBMCEnrollResponse struct {
	DeviceID        uint64                         `codec:"device_id"`
	Endpoint        string                         `codec:"endpoint"`
	Hostname        string                         `codec:"hostname"`
	DNSName         string                         `codec:"dns_name,omitempty"`
	PinSPKISHA256   string                         `codec:"pin_spki_sha256"`
	FactoryCertPEM  []byte                         `codec:"factory_cert_pem,omitempty"`
	FactoryCertMeta QUICBMCFactoryCertMetaResponse `codec:"factory_cert_meta"`
	NewCertPEM      []byte                         `codec:"new_cert_pem,omitempty"`
	CACertPEM       []byte                         `codec:"ca_cert_pem,omitempty"`
	Steps           []QUICBMCEnrollStepResponse    `codec:"steps"`
	Timestamp       int64                          `codec:"timestamp"`
}

// =============================================================================
// QUICServiceHandler wiring
// =============================================================================

// SetBMCEnroller wires the BMCEnroller and DeviceProfileService into the QUIC
// handler after construction. The daemon calls this once the App has been
// initialized so the QUIC enrollment handler can drive the ceremony.
func (h *QUICServiceHandler) SetBMCEnroller(enroller BMCEnroller, profileSvc device.DeviceProfileService) {
	if enroller == nil {
		return
	}
	h.bmcEnrollQUIC = &bmcEnrollQUICHandlers{
		enroller:   enroller,
		profileSvc: profileSvc,
	}
}

// handleBMCCategory handles the BMC category opcode (OpBMCCategory, 0x9F).
// The first byte of the payload selects the sub-operation; the remaining
// bytes carry the MessagePack-encoded sub-request.
func (h *QUICServiceHandler) handleBMCCategory(ctx context.Context, req *quic.Request) *quic.Response {
	if h.bmcEnrollQUIC == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "bmc-enroll"})
	}

	if len(req.Payload) == 0 {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	subOpcode := req.Payload[0]
	subPayload := req.Payload[1:]

	subReq := &quic.Request{
		Opcode:  subOpcode,
		Token:   req.Token,
		Payload: subPayload,
	}

	switch subOpcode {
	case quic.BMCSubEnroll:
		return h.handleBMCEnroll(ctx, subReq)
	default:
		return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: subOpcode})
	}
}

// handleBMCEnroll handles the BMC enrollment ceremony sub-operation
// (BMCSubEnroll, 0x01). It decodes the request, loads the BMC config from
// the profile store, and drives the enrollment ceremony via the BMCEnroller.
func (h *QUICServiceHandler) handleBMCEnroll(ctx context.Context, req *quic.Request) *quic.Response {
	var enrollReq QUICBMCEnrollRequest
	if err := quic.DecodePayload(req.Payload, &enrollReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if enrollReq.ProfileID == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "profile_id"})
	}

	bmcCfg, err := loadBMCConfig(ctx, h.bmcEnrollQUIC.profileSvc, enrollReq.ProfileID, h.bmcEnrollQUIC.enroller)
	if err != nil {
		return h.errorResponse(quic.StatusNotFound, ErrQUICOperationFailed{Op: "bmc_enroll_load_config", Cause: err})
	}

	opts := &app.BMCEnrollOptions{
		ReplaceCertificate: enrollReq.ReplaceCertificate,
		RotatePassword:     enrollReq.RotatePassword,
		DNSRegister:        enrollReq.DNSRegister,
		DANEPublish:        enrollReq.DANEPublish,
	}

	result, err := h.bmcEnrollQUIC.enroller.EnrollBMC(ctx, enrollReq.ProfileID, bmcCfg, opts)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "bmc_enroll", Cause: err})
	}

	resp := quicBMCEnrollResultToResponse(result)

	payload, encErr := quic.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	h.logger.Info("bmc enrollment completed via QUIC",
		"profile_id", enrollReq.ProfileID,
		"device_id", result.DeviceID)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// quicBMCEnrollResultToResponse converts an app.BMCEnrollResult into the
// QUIC wire response struct.
func quicBMCEnrollResultToResponse(r *app.BMCEnrollResult) *QUICBMCEnrollResponse {
	if r == nil {
		return &QUICBMCEnrollResponse{Timestamp: time.Now().Unix()}
	}

	meta := QUICBMCFactoryCertMetaResponse{
		Subject:      r.FactoryCertMeta.Subject,
		Issuer:       r.FactoryCertMeta.Issuer,
		SerialNumber: r.FactoryCertMeta.SerialNumber,
		SPKISHA256:   r.FactoryCertMeta.SPKISHA256,
		SHA256:       r.FactoryCertMeta.SHA256,
	}
	if !r.FactoryCertMeta.NotBefore.IsZero() {
		meta.NotBefore = r.FactoryCertMeta.NotBefore.Unix()
	}
	if !r.FactoryCertMeta.NotAfter.IsZero() {
		meta.NotAfter = r.FactoryCertMeta.NotAfter.Unix()
	}
	if !r.FactoryCertMeta.CapturedAt.IsZero() {
		meta.CapturedAt = r.FactoryCertMeta.CapturedAt.Unix()
	}

	steps := make([]QUICBMCEnrollStepResponse, len(r.Steps))
	for i, s := range r.Steps {
		steps[i] = QUICBMCEnrollStepResponse{
			Name:   s.Name,
			OK:     s.OK,
			Detail: s.Detail,
		}
	}

	return &QUICBMCEnrollResponse{
		DeviceID:        r.DeviceID,
		Endpoint:        r.Endpoint,
		Hostname:        r.Hostname,
		DNSName:         r.DNSName,
		PinSPKISHA256:   r.PinSPKISHA256,
		FactoryCertPEM:  r.FactoryCertPEM,
		FactoryCertMeta: meta,
		NewCertPEM:      r.NewCertPEM,
		CACertPEM:       r.CACertPEM,
		Steps:           steps,
		Timestamp:       time.Now().Unix(),
	}
}
