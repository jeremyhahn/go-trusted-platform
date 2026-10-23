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

package piv

// Wire mapping shared by the QUIC, MCP and REST transports.
//
// Those transports carry the key algorithm as the lowercase string the
// daemon uses ("rsa", "ecdsa", "ed25519"), while the gRPC messages carry the
// PIVAlgorithm enum. The REST and MCP list / slot-info results are the
// daemon's domain structs marshalled WITHOUT json tags, so their keys are the
// Go field names ("FirmwareVersion", "HasKey") rather than the pb snake_case
// names the generic decode expects. The converters below are the single
// canonical mapping the transports delegate to.

import (
	"encoding/json"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// AlgorithmToWire returns the daemon's string form of a key algorithm, or
// ErrUnknownWireValue for a value outside the enum.
func AlgorithmToWire(a platformv1.PIVAlgorithm) (string, error) {
	v, ok := algorithmFromProto[a]
	if !ok {
		return "", &ErrUnknownWireValue{Kind: "algorithm", Value: a.String()}
	}
	return string(v), nil
}

// AlgorithmFromWire maps the daemon's algorithm string onto the pb enum. The
// empty string is UNSPECIFIED; any other unrecognised string is an
// ErrUnknownWireValue rather than a silent UNSPECIFIED.
func AlgorithmFromWire(s string) (platformv1.PIVAlgorithm, error) {
	if s == "" {
		return platformv1.PIVAlgorithm_PIV_ALGORITHM_UNSPECIFIED, nil
	}
	v, ok := algorithmToProto[Algorithm(s)]
	if !ok {
		return platformv1.PIVAlgorithm_PIV_ALGORITHM_UNSPECIFIED, &ErrUnknownWireValue{Kind: "algorithm", Value: s}
	}
	return v, nil
}

// Daemon domain shapes. Field names are the JSON keys; there are no tags.
type deviceJSON struct {
	ID              string
	Name            string
	Manufacturer    string
	Model           string
	Serial          string
	FirmwareVersion string
}

type slotJSON struct {
	ID             string
	Name           string
	Algorithm      string
	HasKey         bool
	HasCertificate bool
}

type slotInfoJSON struct {
	Slot           slotJSON
	PublicKeyPEM   string
	CertificatePEM string
}

func (d deviceJSON) toProto() *platformv1.PIVDevice {
	return &platformv1.PIVDevice{
		Id:              d.ID,
		Name:            d.Name,
		Manufacturer:    d.Manufacturer,
		Model:           d.Model,
		Serial:          d.Serial,
		FirmwareVersion: d.FirmwareVersion,
	}
}

func (s slotJSON) toProto() (*platformv1.PIVSlot, error) {
	return SlotFromWire(s.ID, s.Name, s.Algorithm, s.HasKey, s.HasCertificate)
}

// SlotFromWire builds the pb slot from the daemon's slot fields, refusing an
// unknown algorithm string. It is shared with the QUIC translator.
func SlotFromWire(id, name, algorithm string, hasKey, hasCertificate bool) (*platformv1.PIVSlot, error) {
	alg, err := AlgorithmFromWire(algorithm)
	if err != nil {
		return nil, err
	}
	return &platformv1.PIVSlot{
		Id:             id,
		Name:           name,
		Algorithm:      alg,
		HasKey:         hasKey,
		HasCertificate: hasCertificate,
	}, nil
}

// DecodeListDevicesJSON decodes the REST / MCP ListDevices result
// ({"devices": [...]}).
func DecodeListDevicesJSON(data []byte) (*platformv1.PIVListDevicesResponse, error) {
	var w struct {
		Devices []deviceJSON `json:"devices"`
	}
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, &ErrWireDecode{Message: "list devices", Err: err}
	}
	out := &platformv1.PIVListDevicesResponse{Devices: make([]*platformv1.PIVDevice, 0, len(w.Devices))}
	for _, d := range w.Devices {
		out.Devices = append(out.Devices, d.toProto())
	}
	return out, nil
}

// DecodeListSlotsJSON decodes the REST / MCP ListSlots result
// ({"slots": [...]}).
func DecodeListSlotsJSON(data []byte) (*platformv1.PIVListSlotsResponse, error) {
	var w struct {
		Slots []slotJSON `json:"slots"`
	}
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, &ErrWireDecode{Message: "list slots", Err: err}
	}
	out := &platformv1.PIVListSlotsResponse{Slots: make([]*platformv1.PIVSlot, 0, len(w.Slots))}
	for _, s := range w.Slots {
		slot, err := s.toProto()
		if err != nil {
			return nil, err
		}
		out.Slots = append(out.Slots, slot)
	}
	return out, nil
}

// DecodeSlotInfoJSON decodes the REST / MCP SlotInfo result (the bare
// domain struct).
func DecodeSlotInfoJSON(data []byte) (*platformv1.PIVSlotInfoResponse, error) {
	var w slotInfoJSON
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, &ErrWireDecode{Message: "slot info", Err: err}
	}
	slot, err := w.Slot.toProto()
	if err != nil {
		return nil, err
	}
	return &platformv1.PIVSlotInfoResponse{
		Slot:           slot,
		PublicKeyPem:   w.PublicKeyPEM,
		CertificatePem: w.CertificatePEM,
	}, nil
}
