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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
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
		req.Body = io.NopCloser(bytes.NewReader(body))
		next(w, req)
	}
}
