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

package quic

// FIDO2 wire support for the QUIC transport.
//
// The FIDO2 sub-operations multiplex under OpFIDO2Category (0x9D). The daemon
// dispatcher (pkg/api/daemon/phase35_quic.go::fido2QUICDispatch) decodes each
// request into a quicwire.FIDO2*Req struct and answers with a
// quicwire.FIDO2*Resp struct. The credential role travels as a string rather
// than the FIDO2Role enum, and the Info reply is flat where the pb reply
// nests the fields under FIDO2DeviceInfo.

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	fido2sdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/fido2"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

var fido2RequestEncoders = map[string]categoryRequestEncoder{
	platformv1.FIDO2Service_WaitDevice_FullMethodName: requestEncoder(platformv1.FIDO2Service_WaitDevice_FullMethodName,
		func(r *platformv1.FIDO2WaitDeviceRequest) (interface{}, error) {
			return &quicwire.FIDO2WaitDeviceReq{TimeoutSeconds: r.GetTimeoutSeconds()}, nil
		}),
	platformv1.FIDO2Service_Info_FullMethodName: requestEncoder(platformv1.FIDO2Service_Info_FullMethodName,
		func(r *platformv1.FIDO2InfoRequest) (interface{}, error) {
			return &quicwire.FIDO2InfoReq{Device: r.GetDevice()}, nil
		}),
	platformv1.FIDO2Service_Register_FullMethodName: requestEncoder(platformv1.FIDO2Service_Register_FullMethodName,
		func(r *platformv1.FIDO2RegisterRequest) (interface{}, error) {
			role, err := fido2sdk.RoleToWire(r.GetRole())
			if err != nil {
				return nil, err
			}
			return &quicwire.FIDO2RegisterReq{
				Username:   r.GetUsername(),
				Role:       role,
				RequirePIN: r.GetRequirePin(),
				RequireUV:  r.GetRequireUv(),
				RPID:       r.GetRpId(),
			}, nil
		}),
	platformv1.FIDO2Service_Authenticate_FullMethodName: requestEncoder(platformv1.FIDO2Service_Authenticate_FullMethodName,
		func(r *platformv1.FIDO2AuthenticateRequest) (interface{}, error) {
			return &quicwire.FIDO2AuthenticateReq{CredentialID: r.GetCredentialId()}, nil
		}),
}

var fido2ResponseDecoders = map[string]categoryResponseDecoder{
	platformv1.FIDO2Service_ListDevices_FullMethodName: responseDecoder(platformv1.FIDO2Service_ListDevices_FullMethodName,
		func(w *quicwire.FIDO2ListDevicesResp, out *platformv1.FIDO2ListDevicesResponse) error {
			out.Devices = make([]*platformv1.FIDO2Device, 0, len(w.Devices))
			for _, d := range w.Devices {
				out.Devices = append(out.Devices, fido2DeviceFromWire(d))
			}
			return nil
		}),
	platformv1.FIDO2Service_WaitDevice_FullMethodName: responseDecoder(platformv1.FIDO2Service_WaitDevice_FullMethodName,
		func(w *quicwire.FIDO2WaitDeviceResp, out *platformv1.FIDO2WaitDeviceResponse) error {
			out.Device = fido2DeviceFromWire(w.Device)
			return nil
		}),
	platformv1.FIDO2Service_Info_FullMethodName: responseDecoder(platformv1.FIDO2Service_Info_FullMethodName,
		func(w *quicwire.FIDO2InfoResp, out *platformv1.FIDO2InfoResponse) error {
			out.Info = &platformv1.FIDO2DeviceInfo{
				Device:          fido2DeviceFromWire(w.Device),
				Aaguid:          w.AAGUID,
				FirmwareVersion: w.FirmwareVersion,
				Extensions:      w.Extensions,
				Options:         w.Options,
				MaxMsgSize:      w.MaxMsgSize,
			}
			return nil
		}),
	platformv1.FIDO2Service_Register_FullMethodName: responseDecoder(platformv1.FIDO2Service_Register_FullMethodName,
		func(w *quicwire.FIDO2RegisterResp, out *platformv1.FIDO2RegisterResponse) error {
			out.CredentialId = w.CredentialID
			out.Aaguid = w.AAGUID
			out.PublicKeyPem = w.PublicKeyPEM
			return nil
		}),
	platformv1.FIDO2Service_Authenticate_FullMethodName: responseDecoder(platformv1.FIDO2Service_Authenticate_FullMethodName,
		func(w *quicwire.FIDO2AuthenticateResp, out *platformv1.FIDO2AuthenticateResponse) error {
			out.Authenticated = w.Authenticated
			out.Counter = w.Counter
			return nil
		}),
}

// fido2DeviceFromWire maps a daemon device onto the pb type.
func fido2DeviceFromWire(d quicwire.FIDO2Device) *platformv1.FIDO2Device {
	return fido2sdk.DeviceFromWire(d.ID, d.Path, d.Manufacturer, d.Product, d.ProductID, d.VendorID)
}

func init() {
	registerCategoryCodecs(fido2RequestEncoders, fido2ResponseDecoders)
}
