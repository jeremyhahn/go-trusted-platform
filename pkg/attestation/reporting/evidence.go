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

package reporting

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
)

// Evidence is the wire form of a device quote as the verifier consumes it.
//
// It is the JSON contract shared with the control-plane device quote
// verifier (`DeviceQuoteEvidence` in pkg/api/daemon): the same four fields
// with the same names. The collector produces it, the verifier parses it,
// and a test in the daemon package asserts the two agree — the shape is
// declared here so a background collector does not import an API layer.
type Evidence struct {
	// Quote is the marshaled TPMS_ATTEST structure the TPM produced.
	Quote []byte `json:"quote"`
	// Signature is the attestation-key signature over Quote.
	Signature []byte `json:"signature"`
	// Nonce is the collector-issued anti-replay value. The quote's extraData
	// carries QualifyingData(Nonce, ChannelBinding), not the bare nonce.
	Nonce []byte `json:"nonce"`
	// PCRs maps PCR index to the value the device read for it.
	PCRs map[int][]byte `json:"pcrs"`
	// ChannelBinding is the TLS exporter value of the connection the quote
	// was collected over (xkms.PeerChannelBindingExporterLabel).
	ChannelBinding []byte `json:"channel_binding,omitempty"`
}

// Encode serialises the evidence for the verifier.
func (e *Evidence) Encode() ([]byte, error) {
	if e == nil {
		return nil, ErrInvalidEvidence{Reason: "nil evidence"}
	}
	if len(e.Quote) == 0 || len(e.Signature) == 0 || len(e.Nonce) == 0 || len(e.PCRs) == 0 {
		return nil, ErrInvalidEvidence{Reason: "quote, signature, nonce and pcrs are all required"}
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, ErrInvalidEvidence{Reason: err.Error()}
	}
	return b, nil
}

// hostAttestationEnvelope is the platform REST envelope around a
// CollectHostAttestationResponse as protojson renders it (lowerCamelCase
// field names, bytes as standard base64).
type hostAttestationEnvelope struct {
	Success bool            `json:"success"`
	Code    int             `json:"code"`
	Payload json.RawMessage `json:"payload"`
	Error   json.RawMessage `json:"error"`
}

type hostAttestationPayload struct {
	Attestation *hostAttestationWire `json:"attestation"`
}

type hostAttestationWire struct {
	QuoteData   string        `json:"quoteData"`
	Signature   string        `json:"signature"`
	PCRs        []hostPCRWire `json:"pcrs"`
	PCRDigest   string        `json:"pcrDigest"`
	Nonce       string        `json:"nonce"`
	AKPublicKey string        `json:"akPublicKey"`
}

type hostPCRWire struct {
	Index uint32 `json:"index"`
	Value string `json:"value"`
}

// decodeHostAttestation turns the node's envelope into verifier evidence,
// checking that the node echoed the collector's nonce. It does not verify
// anything cryptographic — that is the verifier's job and it must not be
// duplicated here — but a response that names a different nonce is not
// evidence about this collection and is refused before it reaches one.
func decodeHostAttestation(body []byte, nonce []byte) (*Evidence, error) {
	var env hostAttestationEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, ErrInvalidEvidence{Reason: "response is not a platform envelope: " + err.Error()}
	}
	if !env.Success || len(env.Payload) == 0 {
		return nil, ErrInvalidEvidence{Reason: "response envelope reports failure (code " + strconv.Itoa(env.Code) + ")"}
	}
	var payload hostAttestationPayload
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		return nil, ErrInvalidEvidence{Reason: "payload is not a host attestation: " + err.Error()}
	}
	w := payload.Attestation
	if w == nil {
		return nil, ErrInvalidEvidence{Reason: "payload carries no attestation"}
	}
	quote, err := b64(w.QuoteData, "quoteData")
	if err != nil {
		return nil, err
	}
	sig, err := b64(w.Signature, "signature")
	if err != nil {
		return nil, err
	}
	echoed, err := b64(w.Nonce, "nonce")
	if err != nil {
		return nil, err
	}
	if !equalBytes(echoed, nonce) {
		return nil, ErrNonceMismatch{}
	}
	pcrs := make(map[int][]byte, len(w.PCRs))
	for _, p := range w.PCRs {
		v, err := b64(p.Value, "pcrs["+strconv.FormatUint(uint64(p.Index), 10)+"]")
		if err != nil {
			return nil, err
		}
		if _, dup := pcrs[int(p.Index)]; dup {
			return nil, ErrInvalidEvidence{Reason: "pcr " + strconv.FormatUint(uint64(p.Index), 10) + " reported twice"}
		}
		pcrs[int(p.Index)] = v
	}
	ev := &Evidence{Quote: quote, Signature: sig, Nonce: nonce, PCRs: pcrs}
	if len(ev.PCRs) == 0 {
		return nil, ErrInvalidEvidence{Reason: "node reported no PCR values"}
	}
	return ev, nil
}

func b64(s, field string) ([]byte, error) {
	if s == "" {
		return nil, ErrInvalidEvidence{Reason: field + " is empty"}
	}
	v, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrInvalidEvidence{Reason: field + " is not base64: " + err.Error()}
	}
	return v, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// nodeClockEnvelope is the platform REST envelope around a node's clock
// state. The daemon listener answers the bare payload and the webservice
// wraps it, so both shapes are accepted: an envelope carrying `payload` is
// unwrapped, anything else is read directly.
type nodeClockEnvelope struct {
	Success bool            `json:"success"`
	Code    int             `json:"code"`
	Payload json.RawMessage `json:"payload"`
	Error   json.RawMessage `json:"error"`
}

// nodeClockPayload is the node's clock trust state as the clock route
// serves it. Only `synced` is load-bearing here; the rest of the payload is
// for operators reading the route directly.
type nodeClockPayload struct {
	Synced *bool `json:"synced"`
}

// decodeNodeClock reads a node's clock-state answer.
//
// A payload with no `synced` field is an error, not a false: a node that
// did not say is not a node that said no, and the collector renders the two
// differently.
func decodeNodeClock(body []byte) (bool, error) {
	payload := body
	var env nodeClockEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return false, ErrInvalidClockState{Reason: "response is not JSON: " + err.Error()}
	}
	if len(env.Payload) > 0 {
		if !env.Success {
			return false, ErrInvalidClockState{
				Reason: "response envelope reports failure (code " + strconv.Itoa(env.Code) + ")",
			}
		}
		payload = env.Payload
	}

	var state nodeClockPayload
	if err := json.Unmarshal(payload, &state); err != nil {
		return false, ErrInvalidClockState{Reason: "payload is not a clock state: " + err.Error()}
	}
	if state.Synced == nil {
		return false, ErrInvalidClockState{Reason: "payload carries no synced field"}
	}
	return *state.Synced, nil
}
