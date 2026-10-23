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

// PIV wire support for the QUIC transport.
//
// The PIV sub-operations multiplex under OpPIVCategory (0x9B). The daemon
// dispatcher (pkg/api/daemon/phase35_quic.go::pivQUICDispatch) decodes each
// request into a quicwire.PIV*Req struct and answers with a quicwire.PIV*Resp
// struct, which carries the key algorithm as a string rather than the
// PIVAlgorithm enum.

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	pivsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/piv"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

var pivRequestEncoders = map[string]categoryRequestEncoder{
	platformv1.PIVService_ListSlots_FullMethodName: requestEncoder(platformv1.PIVService_ListSlots_FullMethodName,
		func(r *platformv1.PIVListSlotsRequest) (interface{}, error) {
			return &quicwire.PIVListSlotsReq{Device: r.GetDevice()}, nil
		}),
	platformv1.PIVService_SlotInfo_FullMethodName: requestEncoder(platformv1.PIVService_SlotInfo_FullMethodName,
		func(r *platformv1.PIVSlotInfoRequest) (interface{}, error) {
			return &quicwire.PIVSlotInfoReq{Slot: r.GetSlot(), Device: r.GetDevice()}, nil
		}),
	platformv1.PIVService_Generate_FullMethodName: requestEncoder(platformv1.PIVService_Generate_FullMethodName,
		func(r *platformv1.PIVGenerateRequest) (interface{}, error) {
			algorithm, err := pivsdk.AlgorithmToWire(r.GetAlgorithm())
			if err != nil {
				return nil, err
			}
			return &quicwire.PIVGenerateReq{Slot: r.GetSlot(), Algorithm: algorithm, PIN: r.GetPin()}, nil
		}),
	platformv1.PIVService_Import_FullMethodName: requestEncoder(platformv1.PIVService_Import_FullMethodName,
		func(r *platformv1.PIVImportRequest) (interface{}, error) {
			return &quicwire.PIVImportReq{Slot: r.GetSlot(), PrivateKeyPEM: r.GetPrivateKeyPem(), PIN: r.GetPin()}, nil
		}),
	platformv1.PIVService_Sign_FullMethodName: requestEncoder(platformv1.PIVService_Sign_FullMethodName,
		func(r *platformv1.PIVSignRequest) (interface{}, error) {
			return &quicwire.PIVSignReq{Slot: r.GetSlot(), Payload: r.GetPayload(), PIN: r.GetPin()}, nil
		}),
	platformv1.PIVService_Attest_FullMethodName: requestEncoder(platformv1.PIVService_Attest_FullMethodName,
		func(r *platformv1.PIVAttestRequest) (interface{}, error) {
			return &quicwire.PIVAttestReq{Slot: r.GetSlot()}, nil
		}),
	platformv1.PIVService_Reset_FullMethodName: requestEncoder(platformv1.PIVService_Reset_FullMethodName,
		func(r *platformv1.PIVResetRequest) (interface{}, error) {
			return &quicwire.PIVResetReq{Device: r.GetDevice()}, nil
		}),
}

var pivResponseDecoders = map[string]categoryResponseDecoder{
	platformv1.PIVService_ListDevices_FullMethodName: responseDecoder(platformv1.PIVService_ListDevices_FullMethodName,
		func(w *quicwire.PIVListDevicesResp, out *platformv1.PIVListDevicesResponse) error {
			out.Devices = make([]*platformv1.PIVDevice, 0, len(w.Devices))
			for _, d := range w.Devices {
				out.Devices = append(out.Devices, &platformv1.PIVDevice{
					Id:              d.ID,
					Name:            d.Name,
					Manufacturer:    d.Manufacturer,
					Model:           d.Model,
					Serial:          d.Serial,
					FirmwareVersion: d.FirmwareVersion,
				})
			}
			return nil
		}),
	platformv1.PIVService_ListSlots_FullMethodName: responseDecoder(platformv1.PIVService_ListSlots_FullMethodName,
		func(w *quicwire.PIVListSlotsResp, out *platformv1.PIVListSlotsResponse) error {
			out.Slots = make([]*platformv1.PIVSlot, 0, len(w.Slots))
			for _, s := range w.Slots {
				slot, err := pivSlotFromWire(s)
				if err != nil {
					return err
				}
				out.Slots = append(out.Slots, slot)
			}
			return nil
		}),
	platformv1.PIVService_SlotInfo_FullMethodName: responseDecoder(platformv1.PIVService_SlotInfo_FullMethodName,
		func(w *quicwire.PIVSlotInfoResp, out *platformv1.PIVSlotInfoResponse) error {
			slot, err := pivSlotFromWire(w.Slot)
			if err != nil {
				return err
			}
			out.Slot = slot
			out.PublicKeyPem = w.PublicKeyPEM
			out.CertificatePem = w.CertificatePEM
			return nil
		}),
	platformv1.PIVService_Generate_FullMethodName: responseDecoder(platformv1.PIVService_Generate_FullMethodName,
		func(w *quicwire.PIVGenerateResp, out *platformv1.PIVGenerateResponse) error {
			out.PublicKeyPem = w.PublicKeyPEM
			return nil
		}),
	platformv1.PIVService_Import_FullMethodName: responseDecoder(platformv1.PIVService_Import_FullMethodName,
		func(w *quicwire.PIVImportResp, out *platformv1.PIVImportResponse) error {
			out.Imported = w.Imported
			return nil
		}),
	platformv1.PIVService_Sign_FullMethodName: responseDecoder(platformv1.PIVService_Sign_FullMethodName,
		func(w *quicwire.PIVSignResp, out *platformv1.PIVSignResponse) error {
			out.Signature = w.Signature
			return nil
		}),
	platformv1.PIVService_Attest_FullMethodName: responseDecoder(platformv1.PIVService_Attest_FullMethodName,
		func(w *quicwire.PIVAttestResp, out *platformv1.PIVAttestResponse) error {
			out.AttestationCertPem = w.AttestationCertPEM
			out.AttestationChainPem = w.AttestationChainPEM
			return nil
		}),
	platformv1.PIVService_Reset_FullMethodName: responseDecoder(platformv1.PIVService_Reset_FullMethodName,
		func(w *quicwire.PIVResetResp, out *platformv1.PIVResetResponse) error {
			out.Reset_ = w.Reset
			return nil
		}),
}

// pivSlotFromWire maps a daemon slot onto the pb type through the canonical
// algorithm mapping in sdk/go/services/piv, which refuses an unknown
// algorithm string rather than reporting it as UNSPECIFIED.
func pivSlotFromWire(s quicwire.PIVSlot) (*platformv1.PIVSlot, error) {
	return pivsdk.SlotFromWire(s.ID, s.Name, s.Algorithm, s.HasKey, s.HasCertificate)
}

func init() {
	registerCategoryCodecs(pivRequestEncoders, pivResponseDecoders)
}
