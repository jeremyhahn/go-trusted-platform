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
	"bytes"
	"encoding/json"
	"io"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// RequestFields are the device fields a create or update request may carry.
// The JSON names are the generated proto names, so the Go SDK's
// {device:{...}} envelope and a flat body decode into the same fields.
type RequestFields struct {
	ID         ID     `json:"id,omitempty"`
	AttestPub  string `json:"attest_pub,omitempty"`
	AttestCert string `json:"attest_cert,omitempty"`
	EKCert     string `json:"ek_cert,omitempty"`
	EventLog   []byte `json:"event_log,omitempty"`
	HashAlgoID uint32 `json:"hash_algo_id,omitempty"`
	Model      string `json:"model,omitempty"`
	Serial     string `json:"serial,omitempty"`
	SigningPub string `json:"signing_pub,omitempty"`
	SwitchName string `json:"switch_name,omitempty"`
	SwitchPort string `json:"switch_port,omitempty"`
}

// Request is the one body POST and PUT /api/v1/devices accept on every REST
// listener (#484). It takes the fields flat, inside the proto envelope
// {"device":{...}}, or split across both; a field set in both places to
// different values is refused rather than resolved by precedence.
//
// Keys the device entity has no column for — the console's name, type,
// description, version and tpm_* fields — are not declared, so the decoder
// ignores them. Manufacturer is the one exception: it stands in for an absent
// model.
type Request struct {
	RequestFields
	Device       *RequestFields `json:"device,omitempty"`
	Manufacturer string         `json:"manufacturer,omitempty"`
}

// DecodeRequest reads a device request body and returns the entity it
// describes. It does not require any field; DecodeCreateRequest adds the
// create rules.
func DecodeRequest(body io.Reader) (*entities.Device, error) {
	var req Request
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		return nil, ErrDeviceRequestBody{Cause: err}
	}
	return req.ToDevice()
}

// DecodeCreateRequest reads a device create body and validates it: a device
// is created only with a serial. There is no synthesised fallback — a serial
// the platform invented can never match a TPM at enrollment.
func DecodeCreateRequest(body io.Reader) (*entities.Device, error) {
	d, err := DecodeRequest(body)
	if err != nil {
		return nil, err
	}
	if d.Serial == "" {
		return nil, ErrDeviceSerialRequired{}
	}
	return d, nil
}

// ToDevice merges the flat fields with the envelope and maps the result onto
// a device entity. It fails with ErrDeviceRequestConflict when the two carry
// different values for the same field.
func (r *Request) ToDevice() (*entities.Device, error) {
	fields, err := r.merged()
	if err != nil {
		return nil, err
	}
	model := fields.Model
	if model == "" {
		model = r.Manufacturer
	}
	return &entities.Device{
		ID:         fields.ID.Uint64(),
		AttestPub:  fields.AttestPub,
		AttestCert: fields.AttestCert,
		EKCert:     fields.EKCert,
		EventLog:   fields.EventLog,
		HashAlgoId: fields.HashAlgoID,
		Model:      model,
		Serial:     fields.Serial,
		SigningPub: fields.SigningPub,
		SwitchName: fields.SwitchName,
		SwitchPort: fields.SwitchPort,
	}, nil
}

// merged combines the flat fields and the envelope field by field.
func (r *Request) merged() (RequestFields, error) {
	if r.Device == nil {
		return r.RequestFields, nil
	}
	flat, envelope := r.RequestFields, *r.Device
	m := &fieldMerge{}
	fields := RequestFields{
		ID:         pick(m, "id", flat.ID, envelope.ID),
		AttestPub:  pick(m, "attest_pub", flat.AttestPub, envelope.AttestPub),
		AttestCert: pick(m, "attest_cert", flat.AttestCert, envelope.AttestCert),
		EKCert:     pick(m, "ek_cert", flat.EKCert, envelope.EKCert),
		EventLog:   pickBytes(m, "event_log", flat.EventLog, envelope.EventLog),
		HashAlgoID: pick(m, "hash_algo_id", flat.HashAlgoID, envelope.HashAlgoID),
		Model:      pick(m, "model", flat.Model, envelope.Model),
		Serial:     pick(m, "serial", flat.Serial, envelope.Serial),
		SigningPub: pick(m, "signing_pub", flat.SigningPub, envelope.SigningPub),
		SwitchName: pick(m, "switch_name", flat.SwitchName, envelope.SwitchName),
		SwitchPort: pick(m, "switch_port", flat.SwitchPort, envelope.SwitchPort),
	}
	return fields, m.err
}

// fieldMerge records the first conflict met while merging.
type fieldMerge struct {
	err error
}

func (m *fieldMerge) conflict(field string) {
	if m.err == nil {
		m.err = ErrDeviceRequestConflict{Field: field}
	}
}

// pick returns whichever of flat and envelope is set. When both are set to
// different values it records a conflict on field.
func pick[T comparable](m *fieldMerge, field string, flat, envelope T) T {
	var zero T
	if envelope == zero {
		return flat
	}
	if flat != zero && flat != envelope {
		m.conflict(field)
	}
	return envelope
}

// pickBytes is pick for a byte slice, which is not comparable.
func pickBytes(m *fieldMerge, field string, flat, envelope []byte) []byte {
	if len(envelope) == 0 {
		return flat
	}
	if len(flat) > 0 && !bytes.Equal(flat, envelope) {
		m.conflict(field)
	}
	return envelope
}
