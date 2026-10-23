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

package luks

// Wire mapping shared by the QUIC, MCP and REST transports.
//
// Those transports carry the keyslot type as the lowercase string the daemon
// uses ("passphrase", "fido2", "tpm", "recovery"), while the gRPC messages
// carry the LUKSKeyType enum. The MCP and REST status, slot, info and enroll
// results are the daemon's domain structs marshalled WITHOUT json tags, so their keys
// are the Go field names ("IsLUKS", "TokenID") rather than the pb snake_case
// names the generic decode expects. The converters below are the single
// canonical mapping the transports delegate to.

import (
	"encoding/json"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

var keyTypeToProto = map[KeyType]platformv1.LUKSKeyType{
	KeyTypeUnspecified: platformv1.LUKSKeyType_LUKS_KEY_TYPE_UNSPECIFIED,
	KeyTypePassphrase:  platformv1.LUKSKeyType_LUKS_KEY_TYPE_PASSPHRASE,
	KeyTypeFIDO2:       platformv1.LUKSKeyType_LUKS_KEY_TYPE_FIDO2,
	KeyTypeTPM:         platformv1.LUKSKeyType_LUKS_KEY_TYPE_TPM,
	KeyTypeRecovery:    platformv1.LUKSKeyType_LUKS_KEY_TYPE_RECOVERY,
}

// KeyTypeFromWire maps the daemon's keyslot type string onto the pb enum.
// The empty string is UNSPECIFIED; any other unrecognised string is an
// ErrUnknownWireValue rather than a silent UNSPECIFIED.
func KeyTypeFromWire(s string) (platformv1.LUKSKeyType, error) {
	v, ok := keyTypeToProto[KeyType(s)]
	if !ok {
		return platformv1.LUKSKeyType_LUKS_KEY_TYPE_UNSPECIFIED, &ErrUnknownWireValue{Kind: "key type", Value: s}
	}
	return v, nil
}

// KeyslotFromWire builds the pb keyslot from the daemon's keyslot fields,
// refusing an unknown type string. It is shared with the QUIC translator.
func KeyslotFromWire(slot int32, keyType string, keySize, priority int32) (*platformv1.LUKSKeyslot, error) {
	t, err := KeyTypeFromWire(keyType)
	if err != nil {
		return nil, err
	}
	return &platformv1.LUKSKeyslot{
		Slot:     slot,
		Type:     t,
		KeySize:  keySize,
		Priority: priority,
	}, nil
}

// Daemon domain shapes. Field names are the JSON keys; there are no tags.
type keyslotJSON struct {
	Slot     int32
	Type     string
	KeySize  int32
	Priority int32
}

type statusJSON struct {
	Device      string
	IsLUKS      bool
	Version     int32
	UUID        string
	Label       string
	Cipher      string
	ActiveSlots []int32
}

type listSlotsJSON struct {
	Device string
	Slots  []keyslotJSON
}

type infoJSON struct {
	Device       string
	UUID         string
	Label        string
	Version      int32
	Cipher       string
	KeySize      int32
	SectorSize   int32
	Slots        []keyslotJSON
	MetadataJSON string
}

type enrollJSON struct {
	Slot        int32
	TokenID     string
	RecoveryKey string
}

func keyslotsFromJSON(in []keyslotJSON) ([]*platformv1.LUKSKeyslot, error) {
	out := make([]*platformv1.LUKSKeyslot, 0, len(in))
	for _, s := range in {
		slot, err := KeyslotFromWire(s.Slot, s.Type, s.KeySize, s.Priority)
		if err != nil {
			return nil, err
		}
		out = append(out, slot)
	}
	return out, nil
}

func decodeJSON(data []byte, message string, v interface{}) error {
	if err := json.Unmarshal(data, v); err != nil {
		return &ErrWireDecode{Message: message, Err: err}
	}
	return nil
}

// DecodeStatusJSON decodes the MCP and REST Status result (the bare domain struct).
func DecodeStatusJSON(data []byte) (*platformv1.LUKSStatusResponse, error) {
	var w statusJSON
	if err := decodeJSON(data, "status", &w); err != nil {
		return nil, err
	}
	return &platformv1.LUKSStatusResponse{
		Device:      w.Device,
		IsLuks:      w.IsLUKS,
		Version:     w.Version,
		Uuid:        w.UUID,
		Label:       w.Label,
		Cipher:      w.Cipher,
		ActiveSlots: w.ActiveSlots,
	}, nil
}

// DecodeListSlotsJSON decodes the MCP and REST ListSlots result (the bare domain
// struct).
func DecodeListSlotsJSON(data []byte) (*platformv1.LUKSListSlotsResponse, error) {
	var w listSlotsJSON
	if err := decodeJSON(data, "list slots", &w); err != nil {
		return nil, err
	}
	slots, err := keyslotsFromJSON(w.Slots)
	if err != nil {
		return nil, err
	}
	return &platformv1.LUKSListSlotsResponse{Device: w.Device, Slots: slots}, nil
}

// DecodeInfoJSON decodes the MCP and REST Info result (the bare domain struct).
func DecodeInfoJSON(data []byte) (*platformv1.LUKSInfoResponse, error) {
	var w infoJSON
	if err := decodeJSON(data, "info", &w); err != nil {
		return nil, err
	}
	slots, err := keyslotsFromJSON(w.Slots)
	if err != nil {
		return nil, err
	}
	return &platformv1.LUKSInfoResponse{
		Device:       w.Device,
		Uuid:         w.UUID,
		Label:        w.Label,
		Version:      w.Version,
		Cipher:       w.Cipher,
		KeySize:      w.KeySize,
		SectorSize:   w.SectorSize,
		Slots:        slots,
		MetadataJson: w.MetadataJSON,
	}, nil
}

// DecodeEnrollPassphraseJSON decodes the MCP and REST EnrollPassphrase result.
func DecodeEnrollPassphraseJSON(data []byte) (*platformv1.LUKSEnrollPassphraseResponse, error) {
	var w enrollJSON
	if err := decodeJSON(data, "enroll passphrase", &w); err != nil {
		return nil, err
	}
	return &platformv1.LUKSEnrollPassphraseResponse{Slot: w.Slot}, nil
}

// DecodeEnrollFIDO2JSON decodes the MCP and REST EnrollFIDO2 result.
func DecodeEnrollFIDO2JSON(data []byte) (*platformv1.LUKSEnrollFIDO2Response, error) {
	var w enrollJSON
	if err := decodeJSON(data, "enroll fido2", &w); err != nil {
		return nil, err
	}
	return &platformv1.LUKSEnrollFIDO2Response{Slot: w.Slot, TokenId: w.TokenID}, nil
}

// DecodeEnrollTPMJSON decodes the MCP and REST EnrollTPM result.
func DecodeEnrollTPMJSON(data []byte) (*platformv1.LUKSEnrollTPMResponse, error) {
	var w enrollJSON
	if err := decodeJSON(data, "enroll tpm", &w); err != nil {
		return nil, err
	}
	return &platformv1.LUKSEnrollTPMResponse{Slot: w.Slot, TokenId: w.TokenID}, nil
}

// DecodeEnrollRecoveryJSON decodes the MCP and REST EnrollRecovery result.
func DecodeEnrollRecoveryJSON(data []byte) (*platformv1.LUKSEnrollRecoveryResponse, error) {
	var w enrollJSON
	if err := decodeJSON(data, "enroll recovery", &w); err != nil {
		return nil, err
	}
	return &platformv1.LUKSEnrollRecoveryResponse{Slot: w.Slot, RecoveryKey: w.RecoveryKey}, nil
}
