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

package fido2

// Wire mapping shared by the QUIC, MCP and REST transports.
//
// Those transports carry the credential role as the lowercase string the
// daemon uses ("so", "admin", "user"), while the gRPC messages carry the
// FIDO2Role enum. The REST and MCP results are the daemon's domain structs
// marshalled WITHOUT json tags, so their keys are the Go field names
// ("ProductID", "AAGUID") rather than the pb snake_case names the generic
// decode expects, and the single-object results (WaitDevice, Info, Register,
// Authenticate) are bare structs rather than pb-shaped wrappers. The
// converters below are the single canonical mapping the transports delegate
// to.

import (
	"encoding/json"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

var roleFromProto = map[platformv1.FIDO2Role]Role{
	platformv1.FIDO2Role_FIDO2_ROLE_UNSPECIFIED: RoleUnspecified,
	platformv1.FIDO2Role_FIDO2_ROLE_SO:          RoleSO,
	platformv1.FIDO2Role_FIDO2_ROLE_ADMIN:       RoleAdmin,
	platformv1.FIDO2Role_FIDO2_ROLE_USER:        RoleUser,
}

// RoleToWire returns the daemon's string form of a credential role, or
// ErrUnknownWireValue for a value outside the enum.
func RoleToWire(r platformv1.FIDO2Role) (string, error) {
	v, ok := roleFromProto[r]
	if !ok {
		return "", &ErrUnknownWireValue{Kind: "role", Value: r.String()}
	}
	return string(v), nil
}

// Daemon domain shapes. Field names are the JSON keys; there are no tags.
type deviceJSON struct {
	ID           string
	Path         string
	Manufacturer string
	Product      string
	ProductID    uint32
	VendorID     uint32
}

type infoJSON struct {
	Device          deviceJSON
	AAGUID          string
	FirmwareVersion string
	Extensions      []string
	Options         map[string]bool
	MaxMsgSize      uint32
}

type registerJSON struct {
	CredentialID string
	AAGUID       string
	PublicKeyPEM string
}

type authenticateJSON struct {
	Authenticated bool
	Counter       uint32
}

func (d deviceJSON) toProto() *platformv1.FIDO2Device {
	return &platformv1.FIDO2Device{
		Id:           d.ID,
		Path:         d.Path,
		Manufacturer: d.Manufacturer,
		Product:      d.Product,
		ProductId:    d.ProductID,
		VendorId:     d.VendorID,
	}
}

// DeviceFromWire builds the pb device from the daemon's device fields. It is
// shared with the QUIC translator.
func DeviceFromWire(id, path, manufacturer, product string, productID, vendorID uint32) *platformv1.FIDO2Device {
	return deviceJSON{
		ID: id, Path: path, Manufacturer: manufacturer, Product: product,
		ProductID: productID, VendorID: vendorID,
	}.toProto()
}

// DecodeListDevicesJSON decodes the REST / MCP ListDevices result
// ({"devices": [...]}).
func DecodeListDevicesJSON(data []byte) (*platformv1.FIDO2ListDevicesResponse, error) {
	var w struct {
		Devices []deviceJSON `json:"devices"`
	}
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, &ErrWireDecode{Message: "list devices", Err: err}
	}
	out := &platformv1.FIDO2ListDevicesResponse{Devices: make([]*platformv1.FIDO2Device, 0, len(w.Devices))}
	for _, d := range w.Devices {
		out.Devices = append(out.Devices, d.toProto())
	}
	return out, nil
}

// DecodeWaitDeviceJSON decodes the REST / MCP WaitDevice result (the bare
// device struct).
func DecodeWaitDeviceJSON(data []byte) (*platformv1.FIDO2WaitDeviceResponse, error) {
	var w deviceJSON
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, &ErrWireDecode{Message: "wait device", Err: err}
	}
	return &platformv1.FIDO2WaitDeviceResponse{Device: w.toProto()}, nil
}

// DecodeInfoJSON decodes the REST / MCP Info result (the bare info struct).
func DecodeInfoJSON(data []byte) (*platformv1.FIDO2InfoResponse, error) {
	var w infoJSON
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, &ErrWireDecode{Message: "info", Err: err}
	}
	return &platformv1.FIDO2InfoResponse{Info: &platformv1.FIDO2DeviceInfo{
		Device:          w.Device.toProto(),
		Aaguid:          w.AAGUID,
		FirmwareVersion: w.FirmwareVersion,
		Extensions:      w.Extensions,
		Options:         w.Options,
		MaxMsgSize:      w.MaxMsgSize,
	}}, nil
}

// DecodeRegisterJSON decodes the REST / MCP Register result.
func DecodeRegisterJSON(data []byte) (*platformv1.FIDO2RegisterResponse, error) {
	var w registerJSON
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, &ErrWireDecode{Message: "register", Err: err}
	}
	return &platformv1.FIDO2RegisterResponse{
		CredentialId: w.CredentialID,
		Aaguid:       w.AAGUID,
		PublicKeyPem: w.PublicKeyPEM,
	}, nil
}

// DecodeAuthenticateJSON decodes the REST / MCP Authenticate result.
func DecodeAuthenticateJSON(data []byte) (*platformv1.FIDO2AuthenticateResponse, error) {
	var w authenticateJSON
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, &ErrWireDecode{Message: "authenticate", Err: err}
	}
	return &platformv1.FIDO2AuthenticateResponse{
		Authenticated: w.Authenticated,
		Counter:       w.Counter,
	}, nil
}
