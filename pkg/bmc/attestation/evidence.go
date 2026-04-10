// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import (
	"encoding/json"
	"time"
)

// Vendor identifies a BMC vendor backend.
type Vendor string

const (
	VendorSupermicro Vendor = "supermicro"
	VendorDell       Vendor = "dell"
	VendorHPE        Vendor = "hpe"
	VendorUnknown    Vendor = ""
)

// Action identifies an attestation operation performed against a BMC.
type Action string

const (
	ActionDump     Action = "dump"
	ActionList     Action = "list"
	ActionDownload Action = "download"
	ActionDelete   Action = "delete"
	ActionGetInfo  Action = "getinfo"
	ActionCompare  Action = "compare"
)

// Evidence is an opaque, vendor-specific attestation blob together with
// the minimal metadata required for storage, auditing, and later
// verification. The Raw field is sealed bytes; callers should not parse
// it directly and must feed it back through a vendor backend's GetInfo
// or Compare to obtain a structured view.
type Evidence struct {
	Vendor    Vendor            `json:"vendor"`
	Action    Action            `json:"action"`
	ID        string            `json:"id,omitempty"`
	Nonce     []byte            `json:"nonce,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	Raw       []byte            `json:"raw"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// EvidenceMetadata is a lightweight descriptor returned by List operations.
// It omits the Raw payload so that backends can enumerate BMC-side evidence
// stores without transferring every blob.
type EvidenceMetadata struct {
	Vendor    Vendor            `json:"vendor"`
	ID        string            `json:"id"`
	CreatedAt time.Time         `json:"created_at,omitempty"`
	SizeBytes int64             `json:"size_bytes,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// evidenceJSON is the on-wire envelope used by MarshalJSON/UnmarshalJSON.
// It exists so Raw is emitted as base64 unambiguously and so zero times
// are elided.
type evidenceJSON struct {
	Vendor    Vendor            `json:"vendor"`
	Action    Action            `json:"action"`
	ID        string            `json:"id,omitempty"`
	Nonce     []byte            `json:"nonce,omitempty"`
	CreatedAt *time.Time        `json:"created_at,omitempty"`
	Raw       []byte            `json:"raw"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// MarshalJSON encodes the evidence, omitting a zero CreatedAt.
func (e Evidence) MarshalJSON() ([]byte, error) {
	env := evidenceJSON{
		Vendor:   e.Vendor,
		Action:   e.Action,
		ID:       e.ID,
		Nonce:    e.Nonce,
		Raw:      e.Raw,
		Metadata: e.Metadata,
	}
	if !e.CreatedAt.IsZero() {
		t := e.CreatedAt
		env.CreatedAt = &t
	}
	return json.Marshal(env)
}

// UnmarshalJSON decodes evidence from its JSON envelope.
func (e *Evidence) UnmarshalJSON(b []byte) error {
	var env evidenceJSON
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	e.Vendor = env.Vendor
	e.Action = env.Action
	e.ID = env.ID
	e.Nonce = env.Nonce
	e.Raw = env.Raw
	e.Metadata = env.Metadata
	if env.CreatedAt != nil {
		e.CreatedAt = *env.CreatedAt
	} else {
		e.CreatedAt = time.Time{}
	}
	return nil
}
