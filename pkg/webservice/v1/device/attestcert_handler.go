// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// AttestCertHandler serves POST /api/v1/devices/{id}/attest-cert/record.
type AttestCertHandler interface {
	HandleRecordAttestCert(w http.ResponseWriter, r *http.Request)
}

// maxRecordAttestCertBodyBytes bounds the optional request body, which
// carries at most one boolean.
const maxRecordAttestCertBodyBytes = 4096

// RecordAttestCertRequest is the optional body: whether the platform CA may
// be asked to issue a fresh attestation certificate over the device's
// enrolled attestation public key when no stored certificate passes the
// preflight. An empty body means false.
type RecordAttestCertRequest struct {
	Reissue bool `json:"reissue"`
	// ClearOnRefusal clears the stored certificate when every candidate
	// is refused, so the device reads as absent instead of quarantined.
	ClearOnRefusal bool `json:"clear_on_refusal"`
}

// RecordAttestCertResponse mirrors platform.v1
// RecordAttestationCertificateResponse field for field, with proto JSON
// names, so the SDK's REST transport decodes it into the pb reply.
type RecordAttestCertResponse struct {
	DeviceID uint64 `json:"device_id,string"`
	Serial   string `json:"serial,omitempty"`
	Model    string `json:"model,omitempty"`
	// Changed is false when the record already held this exact certificate
	// and nothing was written.
	Changed bool `json:"changed"`
	// Source is "device", "ca" or "reissued"; SourceDetail is the CA store
	// name it was found under or the CN it was issued with. Both are empty
	// when Cleared.
	Source       string `json:"source"`
	SourceDetail string `json:"source_detail,omitempty"`
	// Reissued is true when the CA was asked to issue a new certificate.
	Reissued          bool       `json:"reissued"`
	Subject           string     `json:"subject"`
	CertificateSerial string     `json:"certificate_serial"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	// AttestCert is the recorded certificate, PEM encoded; empty when
	// Cleared.
	AttestCert string `json:"attest_cert"`
	// Cleared is true when clear_on_refusal removed a refused certificate;
	// Subject, CertificateSerial and NotAfter then describe the certificate
	// that was cleared and Refusal says why it was refused.
	Cleared bool   `json:"cleared"`
	Refusal string `json:"refusal,omitempty"`
}

type attestCertHandler struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	deviceService  platformv1.DeviceServiceServer
}

// NewAttestCertHandler creates the REST handler. It delegates to the
// in-process DeviceService gRPC implementation so REST records exactly what
// gRPC, Unix, QUIC and MCP record, through one fail-closed preflight. A nil
// service yields a nil handler and the route is not registered.
func NewAttestCertHandler(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	deviceService platformv1.DeviceServiceServer,
) AttestCertHandler {
	if deviceService == nil {
		return nil
	}
	return &attestCertHandler{
		logger:         logger,
		responseWriter: responseWriter,
		deviceService:  deviceService,
	}
}

// HandleRecordAttestCert handles POST /api/v1/devices/{id}/attest-cert/record.
func (h *attestCertHandler) HandleRecordAttestCert(w http.ResponseWriter, r *http.Request) {
	deviceID := mux.Vars(r)["id"]
	if deviceID == "" {
		h.responseWriter.Error400(w, r, ErrDeviceIDRequired{})
		return
	}

	var req RecordAttestCertRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRecordAttestCertBodyBytes))
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}

	resp, err := h.deviceService.RecordAttestationCertificate(r.Context(), &platformv1.RecordAttestationCertificateRequest{
		DeviceId:       deviceID,
		Reissue:        req.Reissue,
		ClearOnRefusal: req.ClearOnRefusal,
	})
	if err != nil {
		h.logger.Errorf("device: attestation certificate not recorded: device_id=%s reissue=%t clear_on_refusal=%t error=%v",
			deviceID, req.Reissue, req.ClearOnRefusal, err)
		h.writeRecordError(w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, &RecordAttestCertResponse{
		DeviceID:          resp.GetDeviceId(),
		Serial:            resp.GetSerial(),
		Model:             resp.GetModel(),
		Changed:           resp.GetChanged(),
		Source:            resp.GetSource(),
		SourceDetail:      resp.GetSourceDetail(),
		Reissued:          resp.GetReissued(),
		Subject:           resp.GetSubject(),
		CertificateSerial: resp.GetCertificateSerial(),
		NotAfter:          optionalTime(resp.GetNotAfter()),
		AttestCert:        resp.GetAttestCert(),
		Cleared:           resp.GetCleared(),
		Refusal:           resp.GetRefusal(),
	})
}

// writeRecordError maps the gRPC status onto the HTTP surface. A preflight
// refusal is FailedPrecondition on the wire and a 400 here, carrying every
// candidate and the reason it was refused; the writer has no 412.
func (h *attestCertHandler) writeRecordError(w http.ResponseWriter, r *http.Request, err error) {
	st, ok := status.FromError(err)
	if !ok {
		handleServiceErr(h.responseWriter, w, r, err)
		return
	}
	wrapped := errors.New(st.Message())
	switch st.Code() {
	case codes.InvalidArgument, codes.FailedPrecondition:
		h.responseWriter.Error400(w, r, wrapped)
	case codes.NotFound:
		h.responseWriter.Error404(w, r, wrapped)
	case codes.Aborted:
		// The certificate changed between the refusal and the clear.
		h.responseWriter.Write(w, r, http.StatusConflict, restwire.WebServiceResponse{
			Code:    http.StatusConflict,
			Error:   wrapped.Error(),
			Success: false,
		})
	case codes.PermissionDenied:
		h.responseWriter.Error403(w, r, wrapped, nil)
	case codes.Unauthenticated:
		h.responseWriter.Error401(w, r, wrapped)
	default:
		h.responseWriter.Error500(w, r, wrapped)
	}
}
