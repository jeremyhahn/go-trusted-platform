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
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// maxBootCertificateRequestBytes bounds a boot-certificate request: a name
// and one signature.
const maxBootCertificateRequestBytes = 8 << 10

// bootTransportREST names this transport in ErrBootChannelRequired.
const bootTransportREST = "REST"

// BootHandler serves a diskless node's per-boot routes:
// POST /api/v1/device/boot/certificate and POST /api/v1/device/boot.
type BootHandler interface {
	HandleBootCertificate(w http.ResponseWriter, r *http.Request)
	HandleBootDelivery(w http.ResponseWriter, r *http.Request)
}

type bootHandler struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	service        *BootService
}

// NewBootHandler binds the boot service to HTTP. A nil service yields a nil
// handler so the routes are not registered.
func NewBootHandler(logger *logging.Logger, responseWriter response.HttpWriter, service *BootService) BootHandler {
	if service == nil {
		return nil
	}
	return &bootHandler{logger: logger, responseWriter: responseWriter, service: service}
}

// HandleBootCertificate handles POST /api/v1/device/boot/certificate. The
// node presents no client certificate; it signs the identity and this
// request's own connection value with its IDevID key, and the service checks
// that signature against the recorded chain.
func (h *bootHandler) HandleBootCertificate(w http.ResponseWriter, r *http.Request) {
	nonce, err := BootChannel(r.TLS, bootTransportREST)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	var req provisioning.BootCertificateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBootCertificateRequestBytes)).Decode(&req); err != nil {
		h.responseWriter.Error400(w, r, ErrBootCertificateRequestUnreadable{Cause: err})
		return
	}
	resp, err := h.service.Certificate(r.Context(), BootCertificateInput{
		Identity:     req.Identity,
		ChannelNonce: nonce,
		Signature:    req.Signature,
	})
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.writeJSON(w, resp)
}

// HandleBootDelivery handles POST /api/v1/device/boot. It runs behind the
// mTLS middleware, which has verified the client chain and put the
// certificate's identity in the context; the nonce is derived from this
// request's own connection.
func (h *bootHandler) HandleBootDelivery(w http.ResponseWriter, r *http.Request) {
	identity, ok := r.Context().Value(ContextKeyDeviceSerial).(string)
	if !ok || identity == "" {
		h.responseWriter.Error400(w, r, ErrBootIdentityRequired{})
		return
	}

	var leaf *x509.Certificate
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		leaf = r.TLS.PeerCertificates[0]
	}
	nonce, err := BootChannel(r.TLS, bootTransportREST)
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxAttestEvidenceBytes))
	if err != nil {
		h.responseWriter.Error400(w, r, ErrBootEvidenceUnreadable{Cause: err})
		return
	}
	var req provisioning.BootDeliveryRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.responseWriter.Error400(w, r, ErrBootEvidenceUnreadable{Cause: err})
		return
	}

	resp, err := h.service.Deliver(r.Context(), BootDeliveryInput{
		Identity:     identity,
		PeerLeaf:     leaf,
		ChannelNonce: nonce,
		Evidence:     req.Evidence,
	})
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.logger.Info("diskless boot delivery served",
		"serial", resp.Serial,
		"pcrBaselineSource", resp.PCRBaselineSource)
	h.writeJSON(w, resp)
}

// writeJSON writes raw JSON, matching the other device-facing routes: the
// provisioning client decodes the shape directly, not the operator envelope.
func (h *bootHandler) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.logger.Error(err, "failed to encode boot response")
	}
}

func (h *bootHandler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var (
		identityRequired ErrBootIdentityRequired
		evidenceRequired ErrBootEvidenceRequired
		unreadable       ErrBootEvidenceUnreadable
		unknown          ErrBootIdentityUnknown
		unbound          ErrBootProfileUnbound
		refused          ErrBootRefused
		certRefused      ErrBootCertificateRefused
		channel          ErrBootChannelRequired
	)
	switch {
	case errors.As(err, &identityRequired), errors.As(err, &evidenceRequired), errors.As(err, &unreadable):
		h.responseWriter.Error400(w, r, err)
	case errors.As(err, &channel):
		h.logger.Warn("diskless boot connection cannot be bound", "transport", channel.Transport, "reason", channel.Cause)
		// The connection, not the request, lacks the binding: the refusal is
		// FailedPrecondition on every transport and a 409 here (#665).
		writeGRPCStatusError(h.responseWriter, w, r, err)
	case errors.As(err, &certRefused):
		h.logger.Warn("diskless boot certificate refused", "identity", certRefused.Identity, "reason", certRefused.Cause)
		h.responseWriter.Error403(w, r, err, nil)
	case errors.As(err, &unknown), errors.As(err, &unbound):
		h.responseWriter.Error404(w, r, err)
	case errors.As(err, &refused):
		h.logger.Warn("diskless boot delivery refused", "serial", refused.Serial, "reason", refused.Reason)
		h.responseWriter.Error403(w, r, err, nil)
	default:
		h.logger.Error(err, "diskless boot request failed")
		h.responseWriter.Error500(w, r, err)
	}
}
