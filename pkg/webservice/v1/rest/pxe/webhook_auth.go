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

package pxe

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	// WebhookSignatureHeader carries the install-completion webhook's
	// credential: "sha256=" followed by the lower-case hex HMAC-SHA256 of the
	// raw request body, keyed with pxe.ServiceConfig.WebhookSecret.
	WebhookSignatureHeader = "X-PXE-Webhook-Signature"

	webhookSignaturePrefix = "sha256="

	// maxWebhookBody bounds what is read before the signature is checked;
	// the completion report is a MAC, a hostname, a flag and a message.
	maxWebhookBody = 64 << 10
)

// ErrWebhookSecretUnset is the answer of an enabled webhook with no secret
// configured: it refuses every caller rather than accept one unauthenticated.
type ErrWebhookSecretUnset struct{}

func (ErrWebhookSecretUnset) Error() string {
	return "pxe webhook: no WebhookSecret is configured, so no install-completion report is accepted"
}

// ErrWebhookSignature is the answer to a report whose signature header is
// missing or does not match the body.
type ErrWebhookSignature struct {
	// Missing is true when the request carried no signature header at all.
	Missing bool
}

func (e ErrWebhookSignature) Error() string {
	if e.Missing {
		return "pxe webhook: the " + WebhookSignatureHeader + " header is missing"
	}
	return "pxe webhook: the " + WebhookSignatureHeader + " header does not match the request body"
}

// ErrWebhookBody is the answer to a body that could not be read whole within
// the limit.
type ErrWebhookBody struct {
	Err error
}

func (e ErrWebhookBody) Error() string {
	return "pxe webhook: reading the request body: " + e.Err.Error()
}

func (e ErrWebhookBody) Unwrap() error { return e.Err }

// SignWebhookBody returns the WebhookSignatureHeader value for body under
// secret. A booting node computes the same value over the bytes it sends.
func SignWebhookBody(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return webhookSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

// SetWebhookSecret sets the key the install-completion webhook verifies
// reports with (pxe.ServiceConfig.WebhookSecret). Unset, an enabled webhook
// refuses every report.
func (r *PXERouter) SetWebhookSecret(secret string) {
	r.webhookSecret = []byte(secret)
}

// verifyWebhook admits a request only when its WebhookSignatureHeader is the
// HMAC of its body under the configured secret, compared in constant time.
// The body is read once, bounded, and handed on unchanged.
func (r *PXERouter) verifyWebhook(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if len(r.webhookSecret) == 0 {
			r.respWriter.Error401(w, req, ErrWebhookSecretUnset{})
			return
		}
		got := req.Header.Get(WebhookSignatureHeader)
		if got == "" {
			r.respWriter.Error401(w, req, ErrWebhookSignature{Missing: true})
			return
		}
		var body []byte
		if req.Body != nil {
			var err error
			body, err = io.ReadAll(http.MaxBytesReader(w, req.Body, maxWebhookBody))
			if err != nil {
				r.respWriter.Error400(w, req, ErrWebhookBody{Err: err})
				return
			}
		}
		want := SignWebhookBody(r.webhookSecret, body)
		if !hmac.Equal([]byte(got), []byte(want)) {
			r.respWriter.Error401(w, req, ErrWebhookSignature{})
			return
		}
		if !r.verifyWebhookIdentity(w, req, body) {
			return
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		next(w, req)
	}
}

// WebhookIdentity answers the serial of the certificate recorded for the
// device with the given MAC: the identity that device presented at
// enrollment, which the install-completion webhook binds its caller to.
type WebhookIdentity interface {
	RecordedCertificateSerial(ctx context.Context, mac string) (string, error)
}

// WebhookIdentityFunc adapts a function to WebhookIdentity.
type WebhookIdentityFunc func(ctx context.Context, mac string) (string, error)

// RecordedCertificateSerial calls f.
func (f WebhookIdentityFunc) RecordedCertificateSerial(ctx context.Context, mac string) (string, error) {
	return f(ctx, mac)
}

// SetWebhookIdentity replaces the device-record lookup the webhook binds
// its caller to. Unset, the router reads the PXE device record by MAC
// through its PXE service (GetDeviceByMAC, certificate_serial).
func (r *PXERouter) SetWebhookIdentity(identity WebhookIdentity) {
	r.webhookIdentity = identity
}

// recordedCertificateSerial is the default WebhookIdentity: the PXE device
// record's certificate_serial, read by MAC.
func (r *PXERouter) recordedCertificateSerial(ctx context.Context, mac string) (string, error) {
	if r.webhookIdentity != nil {
		return r.webhookIdentity.RecordedCertificateSerial(ctx, mac)
	}
	if r.server == nil {
		return "", &protorest.ErrServiceUnavailable{Service: "pxe"}
	}
	resp, err := r.server.GetDeviceByMAC(ctx, &platformv1.GetPXEDeviceByMACRequest{MacAddress: mac})
	if err != nil {
		return "", err
	}
	return resp.GetDevice().GetCertificateSerial(), nil
}

// verifyWebhookIdentity enforces the SPEC installer row: the
// install-completion caller authenticates with its device identity over
// mTLS, and reports only for itself. The listener must have verified the
// client's certificate chain (401 otherwise), and the leaf's serial must be
// the certificate recorded on the reported MAC's device (403 otherwise: an
// unknown MAC, a device with no recorded certificate, or another device's).
func (r *PXERouter) verifyWebhookIdentity(w http.ResponseWriter, req *http.Request, body []byte) bool {
	if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 || len(req.TLS.VerifiedChains[0]) == 0 {
		r.respWriter.Error401(w, req, ErrWebhookIdentity{Unauthenticated: true})
		return false
	}
	leaf := req.TLS.VerifiedChains[0][0]

	report := &platformv1.PXEWebhookCompleteRequest{}
	req.Body = io.NopCloser(bytes.NewReader(body))
	if err := protorest.DecodeRequest(req, report); err != nil {
		r.respWriter.Error400(w, req, err)
		return false
	}
	mac := report.GetMacAddress()
	if mac == "" {
		r.respWriter.Error400(w, req, ErrWebhookIdentity{Reason: "the report names no MAC address"})
		return false
	}

	recorded, err := r.recordedCertificateSerial(req.Context(), mac)
	if status.Code(err) == codes.NotFound {
		r.respWriter.Error403(w, req, ErrWebhookIdentity{Reason: "no device is recorded for the reported MAC"}, nil)
		return false
	}
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return false
	}
	if recorded == "" {
		r.respWriter.Error403(w, req, ErrWebhookIdentity{Reason: "the reported device has no recorded certificate"}, nil)
		return false
	}
	if leaf.SerialNumber == nil || leaf.SerialNumber.String() != recorded {
		r.respWriter.Error403(w, req, ErrWebhookIdentity{Reason: "the client certificate is not the reported device's"}, nil)
		return false
	}
	return true
}

// ErrWebhookIdentity refuses an install-completion report whose caller did
// not authenticate as the reported device.
type ErrWebhookIdentity struct {
	// Unauthenticated is set when no verified client certificate was
	// presented.
	Unauthenticated bool
	Reason          string
}

func (e ErrWebhookIdentity) Error() string {
	if e.Unauthenticated {
		return "pxe webhook: a verified device client certificate is required"
	}
	return "pxe webhook: " + e.Reason
}
