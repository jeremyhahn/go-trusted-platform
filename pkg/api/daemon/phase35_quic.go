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

package daemon

import (
	"context"
	"errors"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
)

// QUIC category handlers for Phase 3.5 services. Each handler:
//   1. Validates payload
//   2. Decodes sub-request via quic.DecodePayload (MessagePack/JSON/CBOR)
//   3. Delegates to the corresponding *Service business layer
//   4. Encodes response with quic.EncodePayload
//
// Error mapping mirrors the gRPC handlers: not-configured -> Unavailable,
// validation errors -> InvalidArgument, permission -> PermissionDenied.

// subPayload extracts the sub-opcode and remaining payload.
func subPayload(req *quic.Request) (byte, []byte, *quic.Response) {
	if len(req.Payload) == 0 {
		return 0, nil, &quic.Response{Status: quic.StatusInvalidRequest}
	}
	return req.Payload[0], req.Payload[1:], nil
}

// okResponse encodes v and returns a StatusOK response.
func okResponse(v interface{}) *quic.Response {
	payload, err := quic.EncodePayload(v)
	if err != nil {
		return &quic.Response{Status: quic.StatusInternalError}
	}
	return &quic.Response{Status: quic.StatusOK, Payload: payload}
}

// errResponseFrom maps a service error to the QUIC status byte.
func errResponseFrom(err error) *quic.Response {
	switch {
	case err == nil:
		return &quic.Response{Status: quic.StatusOK}
	case errors.Is(err, ErrCeremonyNotConfigured),
		errors.Is(err, ErrPIVNotConfigured),
		errors.Is(err, ErrLUKSNotConfigured),
		errors.Is(err, ErrFIDO2NotConfigured):
		return &quic.Response{Status: quic.StatusUnavailable}
	case errors.Is(err, ErrLUKSRootRequired):
		return &quic.Response{Status: quic.StatusPermissionDenied}
	case errors.Is(err, ErrCeremonyOfficerRequired),
		errors.Is(err, ErrCeremonyChallengeRequired),
		errors.Is(err, ErrCeremonyCSRRequired),
		errors.Is(err, ErrPIVSlotRequired),
		errors.Is(err, ErrPIVDeviceRequired),
		errors.Is(err, ErrPIVPayloadRequired),
		errors.Is(err, ErrPIVPrivateKeyRequired),
		errors.Is(err, ErrLUKSDeviceRequired),
		errors.Is(err, ErrLUKSPassphraseRequired),
		errors.Is(err, ErrLUKSNewPassphraseRequired),
		errors.Is(err, ErrLUKSCredentialIDRequired),
		errors.Is(err, ErrLUKSSlotRequired),
		errors.Is(err, ErrFIDO2DeviceRequired),
		errors.Is(err, ErrFIDO2UsernameRequired),
		errors.Is(err, ErrFIDO2CredentialRequired):
		return &quic.Response{Status: quic.StatusInvalidArgument}
	}
	return &quic.Response{Status: quic.StatusInternalError}
}

// ceremonyQUICHandlers dispatches ceremony sub-opcodes. Uses map-based
// dispatch for O(1) lookup per project conventions.
type ceremonyQUICHandlers struct {
	service *CeremonyService
}

// Handle routes a ceremony request to the correct sub-handler.
func (h *ceremonyQUICHandlers) Handle(ctx context.Context, req *quic.Request) *quic.Response {
	sub, payload, errResp := subPayload(req)
	if errResp != nil {
		return errResp
	}
	fn, ok := ceremonyQUICDispatch[sub]
	if !ok {
		return &quic.Response{Status: quic.StatusNotImplemented}
	}
	return fn(h, ctx, payload)
}

type ceremonyQUICHandler func(h *ceremonyQUICHandlers, ctx context.Context, payload []byte) *quic.Response

var ceremonyQUICDispatch = map[byte]ceremonyQUICHandler{
	quic.CeremonySubInit:              (*ceremonyQUICHandlers).init,
	quic.CeremonySubStatus:            (*ceremonyQUICHandlers).status,
	quic.CeremonySubClaimCertBegin:    (*ceremonyQUICHandlers).claimCertBegin,
	quic.CeremonySubClaimCertComplete: (*ceremonyQUICHandlers).claimCertComplete,
	quic.CeremonySubClaimShare:        (*ceremonyQUICHandlers).claimShare,
	quic.CeremonySubSignCSR:           (*ceremonyQUICHandlers).signCSR,
}

func (h *ceremonyQUICHandlers) init(ctx context.Context, payload []byte) *quic.Response {
	var in quic.CeremonyInitReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.Init(ctx, &CeremonyInitRequest{
		SOPIN: in.SOPIN, UserPIN: in.UserPIN, Threshold: in.Threshold, Hostname: in.Hostname,
		SANs: in.SANs, CredentialSealStrategy: in.CredentialSealStrategy,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.CeremonyInitResp{
		CeremonyID: out.CeremonyID, State: string(out.State), InitializedAt: out.InitializedAt,
	})
}

func (h *ceremonyQUICHandlers) status(ctx context.Context, _ []byte) *quic.Response {
	out, err := h.service.Status(ctx)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.CeremonyStatusResp{
		CeremonyID:       out.CeremonyID,
		State:            string(out.State),
		Threshold:        out.Threshold,
		OfficersEnrolled: out.OfficersEnrolled,
		OfficersRequired: out.OfficersRequired,
		InitializedAt:    out.InitializedAt,
	})
}

func (h *ceremonyQUICHandlers) claimCertBegin(ctx context.Context, payload []byte) *quic.Response {
	var in quic.CeremonyClaimCertBeginReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.ClaimCertBegin(ctx, &CeremonyClaimCertBeginRequest{
		Username:          in.Username,
		AuthenticatorType: CeremonyAuthenticatorType(in.AuthenticatorType),
		Slot:              in.Slot,
		CredentialID:      in.CredentialID,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.CeremonyClaimCertBeginResp{
		Nonce: out.Nonce, ChallengeID: out.ChallengeID, ExpiresAt: out.ExpiresAt,
	})
}

func (h *ceremonyQUICHandlers) claimCertComplete(ctx context.Context, payload []byte) *quic.Response {
	var in quic.CeremonyClaimCertCompleteReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.ClaimCertComplete(ctx, &CeremonyClaimCertCompleteRequest{
		Username: in.Username, Nonce: in.Nonce, Signature: in.Signature,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.CeremonyClaimCertCompleteResp{
		CertificatePEM: out.CertificatePEM, ChainPEM: out.ChainPEM,
	})
}

func (h *ceremonyQUICHandlers) claimShare(ctx context.Context, payload []byte) *quic.Response {
	var in quic.CeremonyClaimShareReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.ClaimShare(ctx, in.Username)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.CeremonyClaimShareResp{Share: out.Share, Index: out.Index})
}

func (h *ceremonyQUICHandlers) signCSR(ctx context.Context, payload []byte) *quic.Response {
	var in quic.CeremonySignCSRReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.SignCSR(ctx, &CeremonySignCSRRequest{
		Username: in.Username, SOPIN: in.SOPIN, CSRPEM: in.CSRPEM, Role: CeremonyOfficerRole(in.Role),
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.CeremonySignCSRResp{
		CertificatePEM: out.CertificatePEM, ChainPEM: out.ChainPEM,
	})
}

// pivQUICHandlers dispatches PIV sub-opcodes.
type pivQUICHandlers struct {
	service *PIVService
}

type pivQUICHandler func(h *pivQUICHandlers, ctx context.Context, payload []byte) *quic.Response

var pivQUICDispatch = map[byte]pivQUICHandler{
	quic.PIVSubListDevices: (*pivQUICHandlers).listDevices,
	quic.PIVSubListSlots:   (*pivQUICHandlers).listSlots,
	quic.PIVSubSlotInfo:    (*pivQUICHandlers).slotInfo,
	quic.PIVSubGenerate:    (*pivQUICHandlers).generate,
	quic.PIVSubImport:      (*pivQUICHandlers).doImport,
	quic.PIVSubSign:        (*pivQUICHandlers).sign,
	quic.PIVSubAttest:      (*pivQUICHandlers).attest,
	quic.PIVSubReset:       (*pivQUICHandlers).reset,
}

// Handle routes a PIV request.
func (h *pivQUICHandlers) Handle(ctx context.Context, req *quic.Request) *quic.Response {
	sub, payload, errResp := subPayload(req)
	if errResp != nil {
		return errResp
	}
	fn, ok := pivQUICDispatch[sub]
	if !ok {
		return &quic.Response{Status: quic.StatusNotImplemented}
	}
	return fn(h, ctx, payload)
}

func (h *pivQUICHandlers) listDevices(ctx context.Context, _ []byte) *quic.Response {
	d, err := h.service.ListDevices(ctx)
	if err != nil {
		return errResponseFrom(err)
	}
	resp := &quic.PIVListDevicesResp{Devices: make([]quic.PIVDevice, 0, len(d))}
	for _, v := range d {
		resp.Devices = append(resp.Devices, quic.PIVDevice{
			ID: v.ID, Name: v.Name, Manufacturer: v.Manufacturer, Model: v.Model,
			Serial: v.Serial, FirmwareVersion: v.FirmwareVersion,
		})
	}
	return okResponse(resp)
}

func (h *pivQUICHandlers) listSlots(ctx context.Context, payload []byte) *quic.Response {
	var in quic.PIVListSlotsReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	slots, err := h.service.ListSlots(ctx, in.Device)
	if err != nil {
		return errResponseFrom(err)
	}
	resp := &quic.PIVListSlotsResp{Slots: make([]quic.PIVSlot, 0, len(slots))}
	for _, s := range slots {
		resp.Slots = append(resp.Slots, quic.PIVSlot{
			ID: s.ID, Name: s.Name, Algorithm: string(s.Algorithm),
			HasKey: s.HasKey, HasCertificate: s.HasCertificate,
		})
	}
	return okResponse(resp)
}

func (h *pivQUICHandlers) slotInfo(ctx context.Context, payload []byte) *quic.Response {
	var in quic.PIVSlotInfoReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.SlotInfo(ctx, in.Device, in.Slot)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.PIVSlotInfoResp{
		Slot: quic.PIVSlot{
			ID: out.Slot.ID, Name: out.Slot.Name, Algorithm: string(out.Slot.Algorithm),
			HasKey: out.Slot.HasKey, HasCertificate: out.Slot.HasCertificate,
		},
		PublicKeyPEM:   out.PublicKeyPEM,
		CertificatePEM: out.CertificatePEM,
	})
}

func (h *pivQUICHandlers) generate(ctx context.Context, payload []byte) *quic.Response {
	var in quic.PIVGenerateReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.Generate(ctx, &PIVGenerateRequest{
		Slot: in.Slot, Algorithm: PIVAlgorithm(in.Algorithm), PIN: in.PIN,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.PIVGenerateResp{PublicKeyPEM: out.PublicKeyPEM})
}

func (h *pivQUICHandlers) doImport(ctx context.Context, payload []byte) *quic.Response {
	var in quic.PIVImportReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	err := h.service.Import(ctx, &PIVImportRequest{Slot: in.Slot, PrivateKeyPEM: in.PrivateKeyPEM, PIN: in.PIN})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.PIVImportResp{Imported: true})
}

func (h *pivQUICHandlers) sign(ctx context.Context, payload []byte) *quic.Response {
	var in quic.PIVSignReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	sig, err := h.service.Sign(ctx, &PIVSignRequest{Slot: in.Slot, Payload: in.Payload, PIN: in.PIN})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.PIVSignResp{Signature: sig})
}

func (h *pivQUICHandlers) attest(ctx context.Context, payload []byte) *quic.Response {
	var in quic.PIVAttestReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.Attest(ctx, in.Slot)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.PIVAttestResp{
		AttestationCertPEM: out.AttestationCertPEM, AttestationChainPEM: out.AttestationChainPEM,
	})
}

func (h *pivQUICHandlers) reset(ctx context.Context, payload []byte) *quic.Response {
	var in quic.PIVResetReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	if err := h.service.Reset(ctx, in.Device); err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.PIVResetResp{Reset: true})
}

// luksQUICHandlers dispatches LUKS sub-opcodes.
type luksQUICHandlers struct {
	service *LUKSService
}

type luksQUICHandler func(h *luksQUICHandlers, ctx context.Context, payload []byte) *quic.Response

var luksQUICDispatch = map[byte]luksQUICHandler{
	quic.LUKSSubStatus:           (*luksQUICHandlers).status,
	quic.LUKSSubListSlots:        (*luksQUICHandlers).listSlots,
	quic.LUKSSubInfo:             (*luksQUICHandlers).info,
	quic.LUKSSubEnrollPassphrase: (*luksQUICHandlers).enrollPassphrase,
	quic.LUKSSubEnrollFIDO2:      (*luksQUICHandlers).enrollFIDO2,
	quic.LUKSSubEnrollTPM:        (*luksQUICHandlers).enrollTPM,
	quic.LUKSSubEnrollRecovery:   (*luksQUICHandlers).enrollRecovery,
	quic.LUKSSubRemoveKey:        (*luksQUICHandlers).removeKey,
	quic.LUKSSubTestUnlock:       (*luksQUICHandlers).testUnlock,
	quic.LUKSSubChangePassphrase: (*luksQUICHandlers).changePassphrase,
}

// Handle routes a LUKS request.
func (h *luksQUICHandlers) Handle(ctx context.Context, req *quic.Request) *quic.Response {
	sub, payload, errResp := subPayload(req)
	if errResp != nil {
		return errResp
	}
	fn, ok := luksQUICDispatch[sub]
	if !ok {
		return &quic.Response{Status: quic.StatusNotImplemented}
	}
	return fn(h, ctx, payload)
}

func (h *luksQUICHandlers) encodeSlots(slots []LUKSKeyslot) []quic.LUKSKeyslot {
	out := make([]quic.LUKSKeyslot, 0, len(slots))
	for _, s := range slots {
		out = append(out, quic.LUKSKeyslot{
			Slot: s.Slot, Type: string(s.Type), KeySize: s.KeySize, Priority: s.Priority,
		})
	}
	return out
}

func (h *luksQUICHandlers) status(ctx context.Context, payload []byte) *quic.Response {
	var in quic.LUKSStatusReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.Status(ctx, in.Device)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.LUKSStatusResp{
		Device: out.Device, IsLUKS: out.IsLUKS, Version: out.Version,
		UUID: out.UUID, Label: out.Label, Cipher: out.Cipher, ActiveSlots: out.ActiveSlots,
	})
}

func (h *luksQUICHandlers) listSlots(ctx context.Context, payload []byte) *quic.Response {
	var in quic.LUKSListSlotsReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.ListSlots(ctx, in.Device)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.LUKSListSlotsResp{Device: out.Device, Slots: h.encodeSlots(out.Slots)})
}

func (h *luksQUICHandlers) info(ctx context.Context, payload []byte) *quic.Response {
	var in quic.LUKSInfoReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.Info(ctx, in.Device)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.LUKSInfoResp{
		Device: out.Device, UUID: out.UUID, Label: out.Label, Version: out.Version,
		Cipher: out.Cipher, KeySize: out.KeySize, SectorSize: out.SectorSize,
		Slots: h.encodeSlots(out.Slots), MetadataJSON: out.MetadataJSON,
	})
}

func (h *luksQUICHandlers) enrollPassphrase(ctx context.Context, payload []byte) *quic.Response {
	var in quic.LUKSEnrollPassphraseReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.EnrollPassphrase(ctx, &LUKSEnrollPassphraseRequest{
		Device: in.Device, ExistingPassphrase: in.ExistingPassphrase, NewPassphrase: in.NewPassphrase,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.LUKSEnrollPassphraseResp{Slot: out.Slot})
}

func (h *luksQUICHandlers) enrollFIDO2(ctx context.Context, payload []byte) *quic.Response {
	var in quic.LUKSEnrollFIDO2Req
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.EnrollFIDO2(ctx, &LUKSEnrollFIDO2Request{
		Device: in.Device, ExistingPassphrase: in.ExistingPassphrase, CredentialID: in.CredentialID,
		RequirePIN: in.RequirePIN, RequireUV: in.RequireUV,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.LUKSEnrollFIDO2Resp{Slot: out.Slot, TokenID: out.TokenID})
}

func (h *luksQUICHandlers) enrollTPM(ctx context.Context, payload []byte) *quic.Response {
	var in quic.LUKSEnrollTPMReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.EnrollTPM(ctx, &LUKSEnrollTPMRequest{
		Device: in.Device, ExistingPassphrase: in.ExistingPassphrase, PCRs: in.PCRs, Handle: in.Handle,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.LUKSEnrollTPMResp{Slot: out.Slot, TokenID: out.TokenID})
}

func (h *luksQUICHandlers) enrollRecovery(ctx context.Context, payload []byte) *quic.Response {
	var in quic.LUKSEnrollRecoveryReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.EnrollRecovery(ctx, &LUKSEnrollRecoveryRequest{
		Device: in.Device, ExistingPassphrase: in.ExistingPassphrase,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.LUKSEnrollRecoveryResp{Slot: out.Slot, RecoveryKey: out.RecoveryKey})
}

func (h *luksQUICHandlers) removeKey(ctx context.Context, payload []byte) *quic.Response {
	var in quic.LUKSRemoveKeyReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	if err := h.service.RemoveKey(ctx, &LUKSRemoveKeyRequest{Device: in.Device, Slot: in.Slot}); err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.LUKSRemoveKeyResp{Removed: true})
}

func (h *luksQUICHandlers) testUnlock(ctx context.Context, payload []byte) *quic.Response {
	var in quic.LUKSTestUnlockReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	ok, err := h.service.TestUnlock(ctx, &LUKSTestUnlockRequest{Device: in.Device, Slot: in.Slot})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.LUKSTestUnlockResp{Unlocked: ok})
}

func (h *luksQUICHandlers) changePassphrase(ctx context.Context, payload []byte) *quic.Response {
	var in quic.LUKSChangePassphraseReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	err := h.service.ChangePassphrase(ctx, &LUKSChangePassphraseRequest{
		Device: in.Device, Slot: in.Slot, OldPassphrase: in.OldPassphrase, NewPassphrase: in.NewPassphrase,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.LUKSChangePassphraseResp{Changed: true})
}

// fido2QUICHandlers dispatches FIDO2 sub-opcodes.
type fido2QUICHandlers struct {
	service *FIDO2Service
}

type fido2QUICHandler func(h *fido2QUICHandlers, ctx context.Context, payload []byte) *quic.Response

var fido2QUICDispatch = map[byte]fido2QUICHandler{
	quic.FIDO2SubListDevices:  (*fido2QUICHandlers).listDevices,
	quic.FIDO2SubWaitDevice:   (*fido2QUICHandlers).waitDevice,
	quic.FIDO2SubInfo:         (*fido2QUICHandlers).info,
	quic.FIDO2SubRegister:     (*fido2QUICHandlers).register,
	quic.FIDO2SubAuthenticate: (*fido2QUICHandlers).authenticate,
}

// Handle routes a FIDO2 request.
func (h *fido2QUICHandlers) Handle(ctx context.Context, req *quic.Request) *quic.Response {
	sub, payload, errResp := subPayload(req)
	if errResp != nil {
		return errResp
	}
	fn, ok := fido2QUICDispatch[sub]
	if !ok {
		return &quic.Response{Status: quic.StatusNotImplemented}
	}
	return fn(h, ctx, payload)
}

func (h *fido2QUICHandlers) encodeDevice(d FIDO2Device) quic.FIDO2Device {
	return quic.FIDO2Device{
		ID: d.ID, Path: d.Path, Manufacturer: d.Manufacturer, Product: d.Product,
		ProductID: d.ProductID, VendorID: d.VendorID,
	}
}

func (h *fido2QUICHandlers) listDevices(ctx context.Context, _ []byte) *quic.Response {
	devices, err := h.service.ListDevices(ctx)
	if err != nil {
		return errResponseFrom(err)
	}
	resp := &quic.FIDO2ListDevicesResp{Devices: make([]quic.FIDO2Device, 0, len(devices))}
	for _, d := range devices {
		resp.Devices = append(resp.Devices, h.encodeDevice(d))
	}
	return okResponse(resp)
}

func (h *fido2QUICHandlers) waitDevice(ctx context.Context, payload []byte) *quic.Response {
	var in quic.FIDO2WaitDeviceReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	var timeout time.Duration
	if in.TimeoutSeconds > 0 {
		timeout = time.Duration(in.TimeoutSeconds) * time.Second
	}
	dev, err := h.service.WaitDevice(ctx, timeout)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.FIDO2WaitDeviceResp{Device: h.encodeDevice(*dev)})
}

func (h *fido2QUICHandlers) info(ctx context.Context, payload []byte) *quic.Response {
	var in quic.FIDO2InfoReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.Info(ctx, in.Device)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.FIDO2InfoResp{
		Device:          h.encodeDevice(out.Device),
		AAGUID:          out.AAGUID,
		FirmwareVersion: out.FirmwareVersion,
		Extensions:      out.Extensions,
		Options:         out.Options,
		MaxMsgSize:      out.MaxMsgSize,
	})
}

func (h *fido2QUICHandlers) register(ctx context.Context, payload []byte) *quic.Response {
	var in quic.FIDO2RegisterReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.Register(ctx, &FIDO2RegisterRequest{
		Username: in.Username, Role: FIDO2Role(in.Role),
		RequirePIN: in.RequirePIN, RequireUV: in.RequireUV, RPID: in.RPID,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.FIDO2RegisterResp{
		CredentialID: out.CredentialID, AAGUID: out.AAGUID, PublicKeyPEM: out.PublicKeyPEM,
	})
}

func (h *fido2QUICHandlers) authenticate(ctx context.Context, payload []byte) *quic.Response {
	var in quic.FIDO2AuthenticateReq
	if err := quic.DecodePayload(payload, &in); err != nil {
		return &quic.Response{Status: quic.StatusInvalidRequest}
	}
	out, err := h.service.Authenticate(ctx, in.CredentialID)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quic.FIDO2AuthenticateResp{
		Authenticated: out.Authenticated, Counter: out.Counter,
	})
}
