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

// WebhookIdentity answers the IDevID fingerprint (lower-case hex SHA-256 of
// the IDevID certificate's DER) stored at enrolment for the device with the
// given MAC: the binding the install-completion webhook verifies its caller
// against (ruling 673, SPEC installer row).
type WebhookIdentity interface {
	RecordedIDevIDFingerprint(ctx context.Context, mac string) (string, error)
}

// WebhookIdentityFunc adapts a function to WebhookIdentity.
type WebhookIdentityFunc func(ctx context.Context, mac string) (string, error)

// RecordedIDevIDFingerprint calls f.
func (f WebhookIdentityFunc) RecordedIDevIDFingerprint(ctx context.Context, mac string) (string, error) {
	return f(ctx, mac)
}

// SetWebhookIdentity replaces the device-record lookup the webhook binds
// its caller to. Unset, the router asks its PXE service for the IDevID
// fingerprint recorded at enrolment (RecordedIDevIDFingerprint).
func (r *PXERouter) SetWebhookIdentity(identity WebhookIdentity) {
	r.webhookIdentity = identity
}

// recordedIDevIDFingerprint is the default WebhookIdentity: the PXE
// service's RecordedIDevIDFingerprint, read by MAC. A server without that
// method answers service unavailable.
func (r *PXERouter) recordedIDevIDFingerprint(ctx context.Context, mac string) (string, error) {
	if r.webhookIdentity != nil {
		return r.webhookIdentity.RecordedIDevIDFingerprint(ctx, mac)
	}
	identity, ok := r.server.(interface {
		RecordedIDevIDFingerprint(context.Context, string) (string, error)
	})
	if !ok {
		return "", &protorest.ErrServiceUnavailable{Service: "pxe"}
	}
	return identity.RecordedIDevIDFingerprint(ctx, mac)
}

// verifyWebhookIdentity enforces the SPEC installer row: the
// install-completion caller authenticates with its IDevID over mTLS, and
// reports only for itself. The listener must have verified the client's
// certificate chain (401 otherwise), and the hex SHA-256 of the leaf must be
// the IDevID fingerprint stored at enrolment for the reported MAC's device
// (403 otherwise: an unknown MAC, a device with none recorded, or another
// device's), per ruling 673.
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

	recorded, err := r.recordedIDevIDFingerprint(req.Context(), mac)
	if status.Code(err) == codes.NotFound {
		r.respWriter.Error403(w, req, ErrWebhookIdentity{Reason: "no device is recorded for the reported MAC"}, nil)
		return false
	}
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return false
	}
	if recorded == "" {
		r.respWriter.Error403(w, req, ErrWebhookIdentity{Reason: "the reported device has no IDevID recorded at enrolment"}, nil)
		return false
	}
	sum := sha256.Sum256(leaf.Raw)
	fingerprint := hex.EncodeToString(sum[:])
	if !hmac.Equal([]byte(fingerprint), []byte(recorded)) {
		r.respWriter.Error403(w, req, ErrWebhookIdentity{Reason: "the client certificate is not the reported device's"}, nil)
		return false
	}
	// The lookup above is an early refusal only: enrolment can record a
	// new IDevID before the transition, so the handler hands the
	// authenticated fingerprint to the backend, which compares it again
	// under the device lock it transitions under (#1896 Codex r2).
	*req = *req.WithContext(context.WithValue(req.Context(), webhookFingerprintKey{}, fingerprint))
	return true
}

// webhookFingerprintKey carries the authenticated IDevID fingerprint from
// the webhook check to the completion handler.
type webhookFingerprintKey struct{}

// WebhookCompleter is the backend's compare-and-transition for the
// install-completion webhook: under the device lock it compares the
// authenticated IDevID fingerprint with the one recorded at enrolment and
// only then applies the report. A mismatch is PermissionDenied, an unknown
// MAC NotFound.
type WebhookCompleter interface {
	WebhookCompleteForIDevID(ctx context.Context, req *platformv1.PXEWebhookCompleteRequest, fingerprint string) (*platformv1.PXEWebhookCompleteResponse, error)
}

// completeWebhook applies an authenticated report through the backend's
// compare-and-transition. A backend without one is refused: a separate
// lookup and transition would let a superseded IDevID complete the install.
func (r *PXERouter) completeWebhook(w http.ResponseWriter, req *http.Request, report *platformv1.PXEWebhookCompleteRequest) (*platformv1.PXEWebhookCompleteResponse, bool) {
	fingerprint, _ := req.Context().Value(webhookFingerprintKey{}).(string)
	if fingerprint == "" {
		r.respWriter.Error401(w, req, ErrWebhookIdentity{Unauthenticated: true})
		return nil, false
	}
	completer, ok := r.server.(WebhookCompleter)
	if !ok {
		protorest.WriteError(w, req, r.respWriter, &protorest.ErrServiceUnavailable{Service: "pxe"})
		return nil, false
	}
	resp, err := completer.WebhookCompleteForIDevID(req.Context(), report, fingerprint)
	switch status.Code(err) {
	case codes.OK:
		return resp, true
	case codes.PermissionDenied:
		r.respWriter.Error403(w, req, ErrWebhookIdentity{Reason: "the client certificate is not the reported device's"}, nil)
	default:
		protorest.WriteError(w, req, r.respWriter, err)
	}
	return nil, false
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
