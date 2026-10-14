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

// LUKS wire support for the QUIC transport.
//
// The LUKS sub-operations multiplex under OpLUKSCategory (0x9C). The daemon
// dispatcher (pkg/api/daemon/phase35_quic.go::luksQUICDispatch) decodes each
// request into a quicwire.LUKS*Req struct and answers with a quicwire.LUKS*Resp
// struct, which carries the keyslot type as a string rather than the
// LUKSKeyType enum.

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	lukssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

var luksRequestEncoders = map[string]categoryRequestEncoder{
	platformv1.LUKSService_Status_FullMethodName: requestEncoder(platformv1.LUKSService_Status_FullMethodName,
		func(r *platformv1.LUKSStatusRequest) (interface{}, error) {
			return &quicwire.LUKSStatusReq{Device: r.GetDevice()}, nil
		}),
	platformv1.LUKSService_ListSlots_FullMethodName: requestEncoder(platformv1.LUKSService_ListSlots_FullMethodName,
		func(r *platformv1.LUKSListSlotsRequest) (interface{}, error) {
			return &quicwire.LUKSListSlotsReq{Device: r.GetDevice()}, nil
		}),
	platformv1.LUKSService_Info_FullMethodName: requestEncoder(platformv1.LUKSService_Info_FullMethodName,
		func(r *platformv1.LUKSInfoRequest) (interface{}, error) {
			return &quicwire.LUKSInfoReq{Device: r.GetDevice()}, nil
		}),
	platformv1.LUKSService_EnrollPassphrase_FullMethodName: requestEncoder(platformv1.LUKSService_EnrollPassphrase_FullMethodName,
		func(r *platformv1.LUKSEnrollPassphraseRequest) (interface{}, error) {
			return &quicwire.LUKSEnrollPassphraseReq{
				Device:             r.GetDevice(),
				ExistingPassphrase: r.GetExistingPassphrase(),
				NewPassphrase:      r.GetNewPassphrase(),
			}, nil
		}),
	platformv1.LUKSService_EnrollFIDO2_FullMethodName: requestEncoder(platformv1.LUKSService_EnrollFIDO2_FullMethodName,
		func(r *platformv1.LUKSEnrollFIDO2Request) (interface{}, error) {
			return &quicwire.LUKSEnrollFIDO2Req{
				Device:             r.GetDevice(),
				ExistingPassphrase: r.GetExistingPassphrase(),
				CredentialID:       r.GetCredentialId(),
				RequirePIN:         r.GetRequirePin(),
				RequireUV:          r.GetRequireUv(),
			}, nil
		}),
	platformv1.LUKSService_EnrollTPM_FullMethodName: requestEncoder(platformv1.LUKSService_EnrollTPM_FullMethodName,
		func(r *platformv1.LUKSEnrollTPMRequest) (interface{}, error) {
			return &quicwire.LUKSEnrollTPMReq{
				Device:             r.GetDevice(),
				ExistingPassphrase: r.GetExistingPassphrase(),
				PCRs:               r.GetPcrs(),
				Handle:             r.GetHandle(),
			}, nil
		}),
	platformv1.LUKSService_EnrollRecovery_FullMethodName: requestEncoder(platformv1.LUKSService_EnrollRecovery_FullMethodName,
		func(r *platformv1.LUKSEnrollRecoveryRequest) (interface{}, error) {
			return &quicwire.LUKSEnrollRecoveryReq{Device: r.GetDevice(), ExistingPassphrase: r.GetExistingPassphrase()}, nil
		}),
	platformv1.LUKSService_RemoveKey_FullMethodName: requestEncoder(platformv1.LUKSService_RemoveKey_FullMethodName,
		func(r *platformv1.LUKSRemoveKeyRequest) (interface{}, error) {
			return &quicwire.LUKSRemoveKeyReq{Device: r.GetDevice(), Slot: r.GetSlot()}, nil
		}),
	platformv1.LUKSService_TestUnlock_FullMethodName: requestEncoder(platformv1.LUKSService_TestUnlock_FullMethodName,
		func(r *platformv1.LUKSTestUnlockRequest) (interface{}, error) {
			return &quicwire.LUKSTestUnlockReq{Device: r.GetDevice(), Slot: r.GetSlot()}, nil
		}),
	platformv1.LUKSService_ChangePassphrase_FullMethodName: requestEncoder(platformv1.LUKSService_ChangePassphrase_FullMethodName,
		func(r *platformv1.LUKSChangePassphraseRequest) (interface{}, error) {
			return &quicwire.LUKSChangePassphraseReq{
				Device:        r.GetDevice(),
				Slot:          r.GetSlot(),
				OldPassphrase: r.GetOldPassphrase(),
				NewPassphrase: r.GetNewPassphrase(),
			}, nil
		}),
}

var luksResponseDecoders = map[string]categoryResponseDecoder{
	platformv1.LUKSService_Status_FullMethodName: responseDecoder(platformv1.LUKSService_Status_FullMethodName,
		func(w *quicwire.LUKSStatusResp, out *platformv1.LUKSStatusResponse) error {
			out.Device = w.Device
			out.IsLuks = w.IsLUKS
			out.Version = w.Version
			out.Uuid = w.UUID
			out.Label = w.Label
			out.Cipher = w.Cipher
			out.ActiveSlots = w.ActiveSlots
			return nil
		}),
	platformv1.LUKSService_ListSlots_FullMethodName: responseDecoder(platformv1.LUKSService_ListSlots_FullMethodName,
		func(w *quicwire.LUKSListSlotsResp, out *platformv1.LUKSListSlotsResponse) error {
			slots, err := luksKeyslotsFromWire(w.Slots)
			if err != nil {
				return err
			}
			out.Device = w.Device
			out.Slots = slots
			return nil
		}),
	platformv1.LUKSService_Info_FullMethodName: responseDecoder(platformv1.LUKSService_Info_FullMethodName,
		func(w *quicwire.LUKSInfoResp, out *platformv1.LUKSInfoResponse) error {
			slots, err := luksKeyslotsFromWire(w.Slots)
			if err != nil {
				return err
			}
			out.Device = w.Device
			out.Uuid = w.UUID
			out.Label = w.Label
			out.Version = w.Version
			out.Cipher = w.Cipher
			out.KeySize = w.KeySize
			out.SectorSize = w.SectorSize
			out.Slots = slots
			out.MetadataJson = w.MetadataJSON
			return nil
		}),
	platformv1.LUKSService_EnrollPassphrase_FullMethodName: responseDecoder(platformv1.LUKSService_EnrollPassphrase_FullMethodName,
		func(w *quicwire.LUKSEnrollPassphraseResp, out *platformv1.LUKSEnrollPassphraseResponse) error {
			out.Slot = w.Slot
			return nil
		}),
	platformv1.LUKSService_EnrollFIDO2_FullMethodName: responseDecoder(platformv1.LUKSService_EnrollFIDO2_FullMethodName,
		func(w *quicwire.LUKSEnrollFIDO2Resp, out *platformv1.LUKSEnrollFIDO2Response) error {
			out.Slot = w.Slot
			out.TokenId = w.TokenID
			return nil
		}),
	platformv1.LUKSService_EnrollTPM_FullMethodName: responseDecoder(platformv1.LUKSService_EnrollTPM_FullMethodName,
		func(w *quicwire.LUKSEnrollTPMResp, out *platformv1.LUKSEnrollTPMResponse) error {
			out.Slot = w.Slot
			out.TokenId = w.TokenID
			return nil
		}),
	platformv1.LUKSService_EnrollRecovery_FullMethodName: responseDecoder(platformv1.LUKSService_EnrollRecovery_FullMethodName,
		func(w *quicwire.LUKSEnrollRecoveryResp, out *platformv1.LUKSEnrollRecoveryResponse) error {
			out.Slot = w.Slot
			out.RecoveryKey = w.RecoveryKey
			return nil
		}),
	platformv1.LUKSService_RemoveKey_FullMethodName: responseDecoder(platformv1.LUKSService_RemoveKey_FullMethodName,
		func(w *quicwire.LUKSRemoveKeyResp, out *platformv1.LUKSRemoveKeyResponse) error {
			out.Removed = w.Removed
			return nil
		}),
	platformv1.LUKSService_TestUnlock_FullMethodName: responseDecoder(platformv1.LUKSService_TestUnlock_FullMethodName,
		func(w *quicwire.LUKSTestUnlockResp, out *platformv1.LUKSTestUnlockResponse) error {
			out.Unlocked = w.Unlocked
			return nil
		}),
	platformv1.LUKSService_ChangePassphrase_FullMethodName: responseDecoder(platformv1.LUKSService_ChangePassphrase_FullMethodName,
		func(w *quicwire.LUKSChangePassphraseResp, out *platformv1.LUKSChangePassphraseResponse) error {
			out.Changed = w.Changed
			return nil
		}),
}

// luksKeyslotsFromWire maps the daemon keyslots onto the pb type through the
// canonical type mapping in sdk/go/services/luks, which refuses an unknown
// type string rather than reporting it as UNSPECIFIED.
func luksKeyslotsFromWire(in []quicwire.LUKSKeyslot) ([]*platformv1.LUKSKeyslot, error) {
	out := make([]*platformv1.LUKSKeyslot, 0, len(in))
	for _, s := range in {
		slot, err := lukssdk.KeyslotFromWire(s.Slot, s.Type, s.KeySize, s.Priority)
		if err != nil {
			return nil, err
		}
		out = append(out, slot)
	}
	return out, nil
}

func init() {
	registerCategoryCodecs(luksRequestEncoders, luksResponseDecoders)
}
