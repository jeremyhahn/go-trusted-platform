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
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// QUIC category handlers for Phase 3.5 services. Each handler:
//   1. Validates payload
//   2. Decodes sub-request via quicwire.DecodePayload (MessagePack/JSON/CBOR)
//   3. Delegates to the corresponding *Service business layer
//   4. Encodes response with quicwire.EncodePayload
//
// Error mapping mirrors the gRPC handlers: not-configured -> Unavailable,
// validation errors -> InvalidArgument, permission -> PermissionDenied.

// subPayload extracts the sub-opcode and remaining payload.
func subPayload(req *quicwire.Request) (byte, []byte, *quicwire.Response) {
	if len(req.Payload) == 0 {
		return 0, nil, &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	return req.Payload[0], req.Payload[1:], nil
}

// okResponse encodes v and returns a StatusOK response.
func okResponse(v interface{}) *quicwire.Response {
	payload, err := quicwire.EncodePayload(v)
	if err != nil {
		return &quicwire.Response{Status: quicwire.StatusInternalError}
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: payload}
}

// errResponseFrom maps a service error to the QUIC status byte.
func errResponseFrom(err error) *quicwire.Response {
	if err == nil {
		return &quicwire.Response{Status: quicwire.StatusOK}
	}
	for _, refusal := range phase35QUICRefusals {
		if errors.Is(err, refusal.sentinel) {
			// The message names the sentinel, as the gRPC status message and
			// the REST body do, so a client can tell one refusal from
			// another carrying the same status byte.
			return &quicwire.Response{Status: refusal.status, Payload: []byte(err.Error())}
		}
	}
	return &quicwire.Response{Status: quicwire.StatusInternalError}
}

// phase35QUICRefusal pairs a typed service refusal with its QUIC status byte.
type phase35QUICRefusal struct {
	sentinel error
	status   byte
}

// phase35QUICRefusals is the one error-to-status table the ceremony, PIV,
// LUKS and FIDO2 QUIC handlers share. Each row matches the status the REST
// and gRPC mappers give the same sentinel (docs/daemon/api.md §4, status
// bytes). Order matters only where one error wraps two sentinels.
var phase35QUICRefusals = []phase35QUICRefusal{
	{ErrPIVKeyImportUnsupported, quicwire.StatusNotImplemented},
	{ErrCeremonyNotConfigured, quicwire.StatusUnavailable},
	{ErrPIVNotConfigured, quicwire.StatusUnavailable},
	{ErrLUKSNotConfigured, quicwire.StatusUnavailable},
	{ErrFIDO2NotConfigured, quicwire.StatusUnavailable},
	{ErrLUKSRootRequired, quicwire.StatusPermissionDenied},
	{ErrLUKSFIDO2PINUnsupported, quicwire.StatusInvalidArgument},
	{ErrCeremonyOfficerRequired, quicwire.StatusInvalidArgument},
	{ErrCeremonyChallengeRequired, quicwire.StatusInvalidArgument},
	{ErrCeremonyCSRRequired, quicwire.StatusInvalidArgument},
	{ErrPIVSlotRequired, quicwire.StatusInvalidArgument},
	{ErrPIVDeviceRequired, quicwire.StatusInvalidArgument},
	{ErrPIVPayloadRequired, quicwire.StatusInvalidArgument},
	{ErrPIVPrivateKeyRequired, quicwire.StatusInvalidArgument},
	{ErrLUKSDeviceRequired, quicwire.StatusInvalidArgument},
	{ErrLUKSPassphraseRequired, quicwire.StatusInvalidArgument},
	{ErrLUKSNewPassphraseRequired, quicwire.StatusInvalidArgument},
	{ErrLUKSCredentialIDRequired, quicwire.StatusInvalidArgument},
	{ErrLUKSSlotRequired, quicwire.StatusInvalidArgument},
	{ErrLUKSPCRInvalid, quicwire.StatusInvalidArgument},
	{ErrFIDO2DeviceRequired, quicwire.StatusInvalidArgument},
	{ErrFIDO2UsernameRequired, quicwire.StatusInvalidArgument},
	{ErrFIDO2CredentialRequired, quicwire.StatusInvalidArgument},
}

// ceremonyQUICHandlers dispatches ceremony sub-opcodes. Uses map-based
// dispatch for O(1) lookup per project conventions.
type ceremonyQUICHandlers struct {
	service *CeremonyService
}

// Handle routes a ceremony request to the correct sub-handler.
func (h *ceremonyQUICHandlers) Handle(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	sub, payload, errResp := subPayload(req)
	if errResp != nil {
		return errResp
	}
	if denied := quic.AuthorizeSubOpcode(ctx, quic.CeremonySubOpcodePermissions, sub); denied != nil {
		return denied
	}
	fn, ok := ceremonyQUICDispatch[sub]
	if !ok {
		return &quicwire.Response{Status: quicwire.StatusNotImplemented}
	}
	return fn(h, ctx, payload)
}

type ceremonyQUICHandler func(h *ceremonyQUICHandlers, ctx context.Context, payload []byte) *quicwire.Response

var ceremonyQUICDispatch = map[byte]ceremonyQUICHandler{
	quicwire.CeremonySubInit:               (*ceremonyQUICHandlers).init,
	quicwire.CeremonySubStatus:             (*ceremonyQUICHandlers).status,
	quicwire.CeremonySubClaimCertBegin:     (*ceremonyQUICHandlers).claimCertBegin,
	quicwire.CeremonySubClaimCertComplete:  (*ceremonyQUICHandlers).claimCertComplete,
	quicwire.CeremonySubClaimShareBegin:    (*ceremonyQUICHandlers).claimShareBegin,
	quicwire.CeremonySubClaimShareComplete: (*ceremonyQUICHandlers).claimShareComplete,
	quicwire.CeremonySubSignCSR:            (*ceremonyQUICHandlers).signCSR,
}

func (h *ceremonyQUICHandlers) init(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.CeremonyInitReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.Init(ctx, &CeremonyInitRequest{
		SOPIN: in.SOPIN, UserPIN: in.UserPIN, Threshold: in.Threshold, Hostname: in.Hostname,
		SANs: in.SANs, CredentialSealStrategy: in.CredentialSealStrategy,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.CeremonyInitResp{
		CeremonyID: out.CeremonyID, State: string(out.State), InitializedAt: out.InitializedAt,
		AdminCertPEM: out.AdminCertPEM, AdminKeyPEM: out.AdminKeyPEM, SPKIPin: out.SPKIPin,
	})
}

func (h *ceremonyQUICHandlers) status(ctx context.Context, _ []byte) *quicwire.Response {
	out, err := h.service.Status(ctx)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.CeremonyStatusResp{
		CeremonyID:       out.CeremonyID,
		State:            string(out.State),
		Threshold:        out.Threshold,
		OfficersEnrolled: out.OfficersEnrolled,
		OfficersRequired: out.OfficersRequired,
		InitializedAt:    out.InitializedAt,
	})
}

func (h *ceremonyQUICHandlers) claimCertBegin(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.CeremonyClaimCertBeginReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
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
	return okResponse(&quicwire.CeremonyClaimCertBeginResp{
		Nonce: out.Nonce, ChallengeID: out.ChallengeID, ExpiresAt: out.ExpiresAt,
	})
}

func (h *ceremonyQUICHandlers) claimCertComplete(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.CeremonyClaimCertCompleteReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.ClaimCertComplete(ctx, &CeremonyClaimCertCompleteRequest{
		Username: in.Username, Nonce: in.Nonce, Signature: in.Signature,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.CeremonyClaimCertCompleteResp{
		CertificatePEM: out.CertificatePEM, ChainPEM: out.ChainPEM,
	})
}

func (h *ceremonyQUICHandlers) claimShareBegin(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.CeremonyClaimShareBeginReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.ClaimShareBegin(ctx, &CeremonyClaimShareBeginRequest{Username: in.Username})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.CeremonyClaimShareBeginResp{Nonce: out.Nonce, ExpiresAt: out.ExpiresAt})
}

func (h *ceremonyQUICHandlers) claimShareComplete(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.CeremonyClaimShareCompleteReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.ClaimShareComplete(ctx, &CeremonyClaimShareCompleteRequest{
		Username: in.Username, Nonce: in.Nonce, Signature: in.Signature,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.CeremonyClaimShareCompleteResp{Share: out.Share, Index: out.Index})
}

func (h *ceremonyQUICHandlers) signCSR(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.CeremonySignCSRReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.SignCSR(ctx, &CeremonySignCSRRequest{
		Username: in.Username, SOPIN: in.SOPIN, CSRPEM: in.CSRPEM, Role: CeremonyOfficerRole(in.Role),
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.CeremonySignCSRResp{
		CertificatePEM: out.CertificatePEM, ChainPEM: out.ChainPEM,
	})
}

// pivQUICHandlers dispatches PIV sub-opcodes.
type pivQUICHandlers struct {
	service *PIVService
}

type pivQUICHandler func(h *pivQUICHandlers, ctx context.Context, payload []byte) *quicwire.Response

var pivQUICDispatch = map[byte]pivQUICHandler{
	quicwire.PIVSubListDevices: (*pivQUICHandlers).listDevices,
	quicwire.PIVSubListSlots:   (*pivQUICHandlers).listSlots,
	quicwire.PIVSubSlotInfo:    (*pivQUICHandlers).slotInfo,
	quicwire.PIVSubGenerate:    (*pivQUICHandlers).generate,
	quicwire.PIVSubImport:      (*pivQUICHandlers).doImport,
	quicwire.PIVSubSign:        (*pivQUICHandlers).sign,
	quicwire.PIVSubAttest:      (*pivQUICHandlers).attest,
	quicwire.PIVSubReset:       (*pivQUICHandlers).reset,
}

// Handle routes a PIV request.
func (h *pivQUICHandlers) Handle(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	sub, payload, errResp := subPayload(req)
	if errResp != nil {
		return errResp
	}
	if denied := quic.AuthorizeSubOpcode(ctx, quic.PIVSubOpcodePermissions, sub); denied != nil {
		return denied
	}
	fn, ok := pivQUICDispatch[sub]
	if !ok {
		return &quicwire.Response{Status: quicwire.StatusNotImplemented}
	}
	return fn(h, ctx, payload)
}

func (h *pivQUICHandlers) listDevices(ctx context.Context, _ []byte) *quicwire.Response {
	d, err := h.service.ListDevices(ctx)
	if err != nil {
		return errResponseFrom(err)
	}
	resp := &quicwire.PIVListDevicesResp{Devices: make([]quicwire.PIVDevice, 0, len(d))}
	for _, v := range d {
		resp.Devices = append(resp.Devices, quicwire.PIVDevice{
			ID: v.ID, Name: v.Name, Manufacturer: v.Manufacturer, Model: v.Model,
			Serial: v.Serial, FirmwareVersion: v.FirmwareVersion,
		})
	}
	return okResponse(resp)
}

func (h *pivQUICHandlers) listSlots(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.PIVListSlotsReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	slots, err := h.service.ListSlots(ctx, in.Device)
	if err != nil {
		return errResponseFrom(err)
	}
	resp := &quicwire.PIVListSlotsResp{Slots: make([]quicwire.PIVSlot, 0, len(slots))}
	for _, s := range slots {
		resp.Slots = append(resp.Slots, quicwire.PIVSlot{
			ID: s.ID, Name: s.Name, Algorithm: string(s.Algorithm),
			HasKey: s.HasKey, HasCertificate: s.HasCertificate,
		})
	}
	return okResponse(resp)
}

func (h *pivQUICHandlers) slotInfo(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.PIVSlotInfoReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.SlotInfo(ctx, in.Device, in.Slot)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.PIVSlotInfoResp{
		Slot: quicwire.PIVSlot{
			ID: out.Slot.ID, Name: out.Slot.Name, Algorithm: string(out.Slot.Algorithm),
			HasKey: out.Slot.HasKey, HasCertificate: out.Slot.HasCertificate,
		},
		PublicKeyPEM:   out.PublicKeyPEM,
		CertificatePEM: out.CertificatePEM,
	})
}

func (h *pivQUICHandlers) generate(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.PIVGenerateReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	req := &PIVGenerateRequest{
		Slot:       in.Slot,
		Algorithm:  PIVAlgorithm(in.Algorithm),
		PINEnclave: memguard.NewMemoryEnclaveFromString(in.PIN),
	}
	defer req.Destroy()
	out, err := h.service.Generate(ctx, req)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.PIVGenerateResp{PublicKeyPEM: out.PublicKeyPEM})
}

func (h *pivQUICHandlers) doImport(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.PIVImportReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	req := &PIVImportRequest{
		Slot:       in.Slot,
		PrivateKey: memguard.NewMemoryEnclaveFromString(in.PrivateKeyPEM),
		PINEnclave: memguard.NewMemoryEnclaveFromString(in.PIN),
	}
	defer req.Destroy()
	err := h.service.Import(ctx, req)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.PIVImportResp{Imported: true})
}

func (h *pivQUICHandlers) sign(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.PIVSignReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	req := &PIVSignRequest{
		Slot:       in.Slot,
		Payload:    in.Payload,
		PINEnclave: memguard.NewMemoryEnclaveFromString(in.PIN),
	}
	defer req.Destroy()
	sig, err := h.service.Sign(ctx, req)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.PIVSignResp{Signature: sig})
}

func (h *pivQUICHandlers) attest(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.PIVAttestReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.Attest(ctx, in.Slot)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.PIVAttestResp{
		AttestationCertPEM: out.AttestationCertPEM, AttestationChainPEM: out.AttestationChainPEM,
	})
}

func (h *pivQUICHandlers) reset(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.PIVResetReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	if err := h.service.Reset(ctx, in.Device); err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.PIVResetResp{Reset: true})
}

// luksQUICHandlers dispatches LUKS sub-opcodes.
type luksQUICHandlers struct {
	service *LUKSService
}

type luksQUICHandler func(h *luksQUICHandlers, ctx context.Context, payload []byte) *quicwire.Response

var luksQUICDispatch = map[byte]luksQUICHandler{
	quicwire.LUKSSubStatus:           (*luksQUICHandlers).status,
	quicwire.LUKSSubListSlots:        (*luksQUICHandlers).listSlots,
	quicwire.LUKSSubInfo:             (*luksQUICHandlers).info,
	quicwire.LUKSSubEnrollPassphrase: (*luksQUICHandlers).enrollPassphrase,
	quicwire.LUKSSubEnrollFIDO2:      (*luksQUICHandlers).enrollFIDO2,
	quicwire.LUKSSubEnrollTPM:        (*luksQUICHandlers).enrollTPM,
	quicwire.LUKSSubEnrollRecovery:   (*luksQUICHandlers).enrollRecovery,
	quicwire.LUKSSubRemoveKey:        (*luksQUICHandlers).removeKey,
	quicwire.LUKSSubTestUnlock:       (*luksQUICHandlers).testUnlock,
	quicwire.LUKSSubChangePassphrase: (*luksQUICHandlers).changePassphrase,
}

// Handle routes a LUKS request.
func (h *luksQUICHandlers) Handle(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	sub, payload, errResp := subPayload(req)
	if errResp != nil {
		return errResp
	}
	fn, ok := luksQUICDispatch[sub]
	if !ok {
		return &quicwire.Response{Status: quicwire.StatusNotImplemented}
	}
	return fn(h, ctx, payload)
}

func (h *luksQUICHandlers) encodeSlots(slots []LUKSKeyslot) []quicwire.LUKSKeyslot {
	out := make([]quicwire.LUKSKeyslot, 0, len(slots))
	for _, s := range slots {
		out = append(out, quicwire.LUKSKeyslot{
			Slot: s.Slot, Type: string(s.Type), KeySize: s.KeySize, Priority: s.Priority,
		})
	}
	return out
}

func (h *luksQUICHandlers) status(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.LUKSStatusReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.Status(ctx, in.Device)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.LUKSStatusResp{
		Device: out.Device, IsLUKS: out.IsLUKS, Version: out.Version,
		UUID: out.UUID, Label: out.Label, Cipher: out.Cipher, ActiveSlots: out.ActiveSlots,
	})
}

func (h *luksQUICHandlers) listSlots(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.LUKSListSlotsReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.ListSlots(ctx, in.Device)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.LUKSListSlotsResp{Device: out.Device, Slots: h.encodeSlots(out.Slots)})
}

func (h *luksQUICHandlers) info(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.LUKSInfoReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.Info(ctx, in.Device)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.LUKSInfoResp{
		Device: out.Device, UUID: out.UUID, Label: out.Label, Version: out.Version,
		Cipher: out.Cipher, KeySize: out.KeySize, SectorSize: out.SectorSize,
		Slots: h.encodeSlots(out.Slots), MetadataJSON: out.MetadataJSON,
	})
}

func (h *luksQUICHandlers) enrollPassphrase(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.LUKSEnrollPassphraseReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.EnrollPassphrase(ctx, &LUKSEnrollPassphraseRequest{
		Device: in.Device, ExistingPassphrase: in.ExistingPassphrase, NewPassphrase: in.NewPassphrase,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.LUKSEnrollPassphraseResp{Slot: out.Slot})
}

func (h *luksQUICHandlers) enrollFIDO2(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.LUKSEnrollFIDO2Req
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.EnrollFIDO2(ctx, &LUKSEnrollFIDO2Request{
		Device: in.Device, ExistingPassphrase: in.ExistingPassphrase, CredentialID: in.CredentialID,
		RequirePIN: in.RequirePIN, RequireUV: in.RequireUV,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.LUKSEnrollFIDO2Resp{Slot: out.Slot, TokenID: out.TokenID})
}

func (h *luksQUICHandlers) enrollTPM(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.LUKSEnrollTPMReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.EnrollTPM(ctx, &LUKSEnrollTPMRequest{
		Device: in.Device, ExistingPassphrase: in.ExistingPassphrase, PCRs: in.PCRs, Handle: in.Handle,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.LUKSEnrollTPMResp{Slot: out.Slot, TokenID: out.TokenID})
}

func (h *luksQUICHandlers) enrollRecovery(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.LUKSEnrollRecoveryReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.EnrollRecovery(ctx, &LUKSEnrollRecoveryRequest{
		Device: in.Device, ExistingPassphrase: in.ExistingPassphrase,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.LUKSEnrollRecoveryResp{Slot: out.Slot, RecoveryKey: out.RecoveryKey})
}

func (h *luksQUICHandlers) removeKey(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.LUKSRemoveKeyReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	if err := h.service.RemoveKey(ctx, &LUKSRemoveKeyRequest{Device: in.Device, Slot: in.Slot}); err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.LUKSRemoveKeyResp{Removed: true})
}

func (h *luksQUICHandlers) testUnlock(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.LUKSTestUnlockReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	ok, err := h.service.TestUnlock(ctx, &LUKSTestUnlockRequest{Device: in.Device, Slot: in.Slot})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.LUKSTestUnlockResp{Unlocked: ok})
}

func (h *luksQUICHandlers) changePassphrase(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.LUKSChangePassphraseReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	err := h.service.ChangePassphrase(ctx, &LUKSChangePassphraseRequest{
		Device: in.Device, Slot: in.Slot, OldPassphrase: in.OldPassphrase, NewPassphrase: in.NewPassphrase,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.LUKSChangePassphraseResp{Changed: true})
}

// fido2QUICHandlers dispatches FIDO2 sub-opcodes.
type fido2QUICHandlers struct {
	service *FIDO2Service
}

type fido2QUICHandler func(h *fido2QUICHandlers, ctx context.Context, payload []byte) *quicwire.Response

var fido2QUICDispatch = map[byte]fido2QUICHandler{
	quicwire.FIDO2SubListDevices:  (*fido2QUICHandlers).listDevices,
	quicwire.FIDO2SubWaitDevice:   (*fido2QUICHandlers).waitDevice,
	quicwire.FIDO2SubInfo:         (*fido2QUICHandlers).info,
	quicwire.FIDO2SubRegister:     (*fido2QUICHandlers).register,
	quicwire.FIDO2SubAuthenticate: (*fido2QUICHandlers).authenticate,
}

// Handle routes a FIDO2 request.
func (h *fido2QUICHandlers) Handle(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	sub, payload, errResp := subPayload(req)
	if errResp != nil {
		return errResp
	}
	if denied := quic.AuthorizeSubOpcode(ctx, quic.FIDO2SubOpcodePermissions, sub); denied != nil {
		return denied
	}
	fn, ok := fido2QUICDispatch[sub]
	if !ok {
		return &quicwire.Response{Status: quicwire.StatusNotImplemented}
	}
	return fn(h, ctx, payload)
}

func (h *fido2QUICHandlers) encodeDevice(d FIDO2Device) quicwire.FIDO2Device {
	return quicwire.FIDO2Device{
		ID: d.ID, Path: d.Path, Manufacturer: d.Manufacturer, Product: d.Product,
		ProductID: d.ProductID, VendorID: d.VendorID,
	}
}

func (h *fido2QUICHandlers) listDevices(ctx context.Context, _ []byte) *quicwire.Response {
	devices, err := h.service.ListDevices(ctx)
	if err != nil {
		return errResponseFrom(err)
	}
	resp := &quicwire.FIDO2ListDevicesResp{Devices: make([]quicwire.FIDO2Device, 0, len(devices))}
	for _, d := range devices {
		resp.Devices = append(resp.Devices, h.encodeDevice(d))
	}
	return okResponse(resp)
}

func (h *fido2QUICHandlers) waitDevice(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.FIDO2WaitDeviceReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	var timeout time.Duration
	if in.TimeoutSeconds > 0 {
		timeout = time.Duration(in.TimeoutSeconds) * time.Second
	}
	dev, err := h.service.WaitDevice(ctx, timeout)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.FIDO2WaitDeviceResp{Device: h.encodeDevice(*dev)})
}

func (h *fido2QUICHandlers) info(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.FIDO2InfoReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.Info(ctx, in.Device)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.FIDO2InfoResp{
		Device:          h.encodeDevice(out.Device),
		AAGUID:          out.AAGUID,
		FirmwareVersion: out.FirmwareVersion,
		Extensions:      out.Extensions,
		Options:         out.Options,
		MaxMsgSize:      out.MaxMsgSize,
	})
}

func (h *fido2QUICHandlers) register(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.FIDO2RegisterReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.Register(ctx, &FIDO2RegisterRequest{
		Username: in.Username, Role: FIDO2Role(in.Role),
		RequirePIN: in.RequirePIN, RequireUV: in.RequireUV, RPID: in.RPID,
	})
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.FIDO2RegisterResp{
		CredentialID: out.CredentialID, AAGUID: out.AAGUID, PublicKeyPEM: out.PublicKeyPEM,
	})
}

func (h *fido2QUICHandlers) authenticate(ctx context.Context, payload []byte) *quicwire.Response {
	var in quicwire.FIDO2AuthenticateReq
	if err := quicwire.DecodePayload(payload, &in); err != nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest}
	}
	out, err := h.service.Authenticate(ctx, in.CredentialID)
	if err != nil {
		return errResponseFrom(err)
	}
	return okResponse(&quicwire.FIDO2AuthenticateResp{
		Authenticated: out.Authenticated, Counter: out.Counter,
	})
}
