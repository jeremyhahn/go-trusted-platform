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

package backends

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// LUKS FIDO2 handler errors.

// ErrLUKSFIDO2NoXKMSHandler indicates the underlying go-xkms FIDO2 Handler is
// nil. Callers must pass a working Handler from go-xkms or use the default
// constructor.
var ErrLUKSFIDO2NoXKMSHandler = errors.New("luks fido2 handler: xkms handler is nil")

// ErrLUKSFIDO2InvalidCredential indicates the credential ID passed in for
// enrolment was empty or malformed (expected hex-encoded bytes).
var ErrLUKSFIDO2InvalidCredential = errors.New("luks fido2 handler: invalid credential id")

// ErrLUKSFIDO2InvalidToken indicates the FIDO2 LUKS token could not be parsed.
var ErrLUKSFIDO2InvalidToken = errors.New("luks fido2 handler: invalid token payload")

// ErrLUKSFIDO2DeriveFailed indicates the HMAC-SECRET derivation against the
// authenticator failed (device missing, user cancelled, etc.).
var ErrLUKSFIDO2DeriveFailed = errors.New("luks fido2 handler: hmac-secret derivation failed")

// ErrLUKSFIDO2PINUnsupported refuses a PIN-required enrolment before any
// derivation, keyslot or token write: the SDK fido2 re-export has no
// PIN-capable handler (SDK seam #584). It is the API's sentinel, so every
// transport maps the backend's refusal the same way.
var ErrLUKSFIDO2PINUnsupported = daemon.ErrLUKSFIDO2PINUnsupported

// LUKSFIDO2TokenType is the LUKS2 token type stored for trusted-platform
// FIDO2 slots. Mirrors the token type already routed by luksKeySlotTypeMap.
const LUKSFIDO2TokenType = "fido2-manual"

// fido2LUKSToken is the JSON payload we persist in a LUKS2 token when a slot
// is enrolled via HMAC-SECRET. The format is intentionally forward-compatible
// with systemd-cryptsetup's "fido2" token by reusing the credential-id /
// rp-id / salt fields; the extra fields are ignored by systemd but useful
// for operators.
type fido2LUKSToken struct {
	Type         string   `json:"type"`
	Keyslots     []string `json:"keyslots"`
	CredentialID string   `json:"fido2-credential"`
	Salt         string   `json:"fido2-salt"`
	RPID         string   `json:"fido2-rp,omitempty"`
	UPRequired   bool     `json:"fido2-up-required,omitempty"`
}

// LUKSFIDO2EnrollResult is the internal output of an enrol call: the derived
// key (used as the LUKS passphrase) and the JSON token to import.
type LUKSFIDO2EnrollResult struct {
	DerivedKey []byte
	TokenJSON  []byte
	Salt       []byte
}

// luksFIDO2Handler implements LUKSFIDO2Handler (EnrollCredential) by driving
// an HMAC-SECRET ceremony against a go-xkms FIDO2 Handler. Separately it
// exposes DeriveEnroll / DeriveUnlock for the richer token-writing / unlock
// paths so the LUKS backend can generate and consume tokens without leaking
// FIDO2 details.
type luksFIDO2Handler struct {
	logger *logging.Logger
	xkms   fido2.Handler
	rpID   string
}

// Compile-time assertion against the minimum interface.
var _ LUKSFIDO2Handler = (*luksFIDO2Handler)(nil)

// NewLUKSFIDO2Handler builds a LUKSFIDO2Handler around the supplied go-xkms
// FIDO2 handler. Passing a nil handler returns an error — fall back to
// leaving the LUKS backend's FIDO2 handler unset which causes enrolment to
// fail fast with ErrLUKSFIDO2NotWired.
func NewLUKSFIDO2Handler(logger *logging.Logger, h fido2.Handler, rpID string) (*luksFIDO2Handler, error) {
	if h == nil {
		return nil, ErrLUKSFIDO2NoXKMSHandler
	}
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	if rpID == "" {
		rpID = fido2.DefaultConfig.RelyingPartyID
	}
	return &luksFIDO2Handler{logger: logger, xkms: h, rpID: rpID}, nil
}

// EnrollCredential satisfies the minimal LUKSFIDO2Handler interface consumed
// by LUKSBackend.EnrollFIDO2. A fresh 32-byte salt is generated, HMAC-SECRET
// is invoked against the supplied credential, and the derived key bytes are
// returned to be used as the LUKS passphrase.
//
// Callers that need the salt / token payload should use DeriveEnroll
// directly.
func (h *luksFIDO2Handler) EnrollCredential(ctx context.Context, credentialID string, requirePIN, requireUV bool) ([]byte, error) {
	res, err := h.DeriveEnroll(ctx, credentialID, requirePIN, requireUV)
	if err != nil {
		return nil, err
	}
	// The caller receives the derived key only. The salt is encoded in the
	// LUKS2 token by LUKSBackend so it can be reproduced on unlock.
	return res.DerivedKey, nil
}

// DeriveEnroll is the richer API used by the LUKS backend when it wants both
// the derived key *and* the token payload to persist to the LUKS2 header.
// requirePIN is refused with ErrLUKSFIDO2PINUnsupported before any
// derivation, and the token records only the verification it enforced.
func (h *luksFIDO2Handler) DeriveEnroll(ctx context.Context, credentialID string, requirePIN, requireUV bool) (*LUKSFIDO2EnrollResult, error) {
	if requirePIN {
		return nil, ErrLUKSFIDO2PINUnsupported
	}
	if h.xkms == nil {
		return nil, ErrLUKSFIDO2NoXKMSHandler
	}
	credBytes, err := decodeCredentialID(credentialID)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrLUKSFIDO2DeriveFailed, Cause: &MessageError{Msg: fmt.Sprintf("salt: %v", err)}}
	}

	derived, err := h.deriveWithContext(ctx, credBytes, salt, requireUV)
	if err != nil {
		return nil, err
	}

	token := &fido2LUKSToken{
		Type:         LUKSFIDO2TokenType,
		CredentialID: credentialID,
		Salt:         base64.StdEncoding.EncodeToString(salt),
		RPID:         h.rpID,
		UPRequired:   requireUV,
	}
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrLUKSFIDO2DeriveFailed, Cause: &MessageError{Msg: fmt.Sprintf("marshal token: %v", err)}}
	}
	return &LUKSFIDO2EnrollResult{
		DerivedKey: derived,
		TokenJSON:  tokenJSON,
		Salt:       salt,
	}, nil
}

// DeriveUnlock reproduces the HMAC-SECRET derivation for an existing LUKS2
// token. Given the token JSON previously written by DeriveEnroll, it returns
// the LUKS passphrase bytes. Used by the unlock path (the enroll path gets
// the derived key back directly from DeriveEnroll).
func (h *luksFIDO2Handler) DeriveUnlock(ctx context.Context, tokenJSON []byte) ([]byte, error) {
	if h.xkms == nil {
		return nil, ErrLUKSFIDO2NoXKMSHandler
	}
	var token fido2LUKSToken
	if err := json.Unmarshal(tokenJSON, &token); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrLUKSFIDO2InvalidToken, Cause: err}
	}
	credBytes, err := decodeCredentialID(token.CredentialID)
	if err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(token.Salt)
	if err != nil || len(salt) == 0 {
		return nil, &SentinelCauseError{Sentinel: ErrLUKSFIDO2InvalidToken, Cause: &MessageError{Msg: fmt.Sprintf("salt: %v", err)}}
	}
	return h.deriveWithContext(ctx, credBytes, salt, token.UPRequired)
}

// deriveWithContext runs UnlockWithKey (HMAC-SECRET derivation) inside a
// context-aware goroutine so that context cancellation triggers an error
// return rather than waiting for the FIDO2 retry loop to complete.
func (h *luksFIDO2Handler) deriveWithContext(ctx context.Context, credentialID, salt []byte, requireUV bool) ([]byte, error) {
	cfg := fido2.DefaultAuthenticationConfig(credentialID, salt)
	cfg.RelyingPartyID = h.rpID
	cfg.RequireUserVerification = requireUV

	if deadline, ok := ctx.Deadline(); ok {
		cfg.Timeout = time.Until(deadline)
	}

	type derivation struct {
		key []byte
		err error
	}
	ch := make(chan derivation, 1)
	go func() {
		key, err := h.xkms.UnlockWithKey(cfg)
		ch <- derivation{key: key, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrLUKSFIDO2DeriveFailed, Cause: r.err}
		}
		return r.key, nil
	}
}

// decodeCredentialID accepts a credential id encoded as either hex or
// base64-standard, which covers the two representations commonly emitted by
// WebAuthn stacks.
func decodeCredentialID(s string) ([]byte, error) {
	if s == "" {
		return nil, ErrLUKSFIDO2InvalidCredential
	}
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, ErrLUKSFIDO2InvalidCredential
}
