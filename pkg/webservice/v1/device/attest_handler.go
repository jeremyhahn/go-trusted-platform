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

package device

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// AttestHandler serves device attestation verification over REST.
type AttestHandler interface {
	HandleAttestDevice(w http.ResponseWriter, r *http.Request)
}

// maxAttestEvidenceBytes bounds the evidence payload. A TPM quote plus its
// signature and PCR policy is a few kilobytes; the cap exists so an
// unbounded body cannot be used to exhaust memory on an authenticated but
// hostile request.
const maxAttestEvidenceBytes = 1 << 20 // 1 MiB

// AttestRequest is the REST body for POST /api/v1/devices/{id}/attest.
//
// evidence is the same JSON-encoded DeviceQuoteEvidence every other
// transport carries — base64 in JSON — so the wire contract does not fork
// per transport.
type AttestRequest struct {
	Evidence []byte `json:"evidence"`
}

// AttestResponse reports what was verified, not merely that the call
// succeeded. The individual checks are reported alongside the verdict so a
// console can say WHY a device failed rather than only that it did.
type AttestResponse struct {
	DeviceID          uint64    `json:"device_id,string"`
	Serial            string    `json:"serial,omitempty"`
	Model             string    `json:"model,omitempty"`
	Verified          bool      `json:"verified"`
	SignatureValid    bool      `json:"signature_valid"`
	NonceValid        bool      `json:"nonce_valid"`
	PCRsValid         bool      `json:"pcrs_valid"`
	AttestationStatus string    `json:"attestation_status"`
	Message           string    `json:"message,omitempty"`
	AttestedAt        time.Time `json:"attested_at"`
}

// attestHandler delegates to the in-process DeviceService gRPC implementation
// rather than verifying anything itself.
//
// This is the established seam in this package (AttestationServiceServer,
// ComputeServiceServer and nine others reach REST the same way): the REST
// layer binds HTTP and the gRPC service holds the logic, so every transport
// answers from one verifier. Adding a second implementation here is how two
// transports come to disagree about whether a device attested.
//
// Extracting the verifier into a service package is the better end state and
// is #175's scope — the ServiceModule seam the owner has already ruled for —
// not this handler's.
type attestHandler struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	deviceService  platformv1.DeviceServiceServer
}

// NewAttestHandler creates the REST attestation handler. A nil
// deviceService yields a nil handler so the route is not registered at all,
// rather than registered and answering 503 — an absent capability should not
// look like a broken one.
func NewAttestHandler(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	deviceService platformv1.DeviceServiceServer,
) AttestHandler {
	if deviceService == nil {
		return nil
	}
	return &attestHandler{
		logger:         logger,
		responseWriter: responseWriter,
		deviceService:  deviceService,
	}
}

// HandleAttestDevice handles POST /api/v1/devices/{id}/attest.
//
// A failed verification is a 200 carrying a negative verdict, not an error
// status: the caller asked whether the device attests, and "no" is a
// successful answer to that question. Error statuses are reserved for
// requests that could not be evaluated — unparseable evidence, an unknown
// device, or a device with no trustworthy attestation key.
func (h *attestHandler) HandleAttestDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := mux.Vars(r)["id"]
	if deviceID == "" {
		h.responseWriter.Error400(w, r, ErrDeviceIDRequired{})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxAttestEvidenceBytes))
	if err != nil {
		h.responseWriter.Error400(w, r, ErrAttestEvidenceUnreadable{Cause: err})
		return
	}

	var req AttestRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.responseWriter.Error400(w, r, ErrAttestEvidenceUnreadable{Cause: err})
		return
	}
	if len(req.Evidence) == 0 {
		h.responseWriter.Error400(w, r, ErrAttestEvidenceRequired{})
		return
	}

	resp, err := h.deviceService.AttestDevice(r.Context(), &platformv1.AttestDeviceRequest{
		DeviceId: deviceID,
		Evidence: req.Evidence,
	})
	if err != nil {
		h.logger.Errorf("device: attestation could not be evaluated: device_id=%s error=%v", deviceID, err)
		handleServiceErr(h.responseWriter, w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, &AttestResponse{
		DeviceID:          resp.GetDeviceId(),
		Serial:            resp.GetSerial(),
		Model:             resp.GetModel(),
		Verified:          resp.GetVerified(),
		SignatureValid:    resp.GetSignatureValid(),
		NonceValid:        resp.GetNonceValid(),
		PCRsValid:         resp.GetPcrsValid(),
		AttestationStatus: resp.GetAttestationStatus(),
		Message:           resp.GetMessage(),
		AttestedAt:        resp.GetAttestedAt().AsTime(),
	})
}
