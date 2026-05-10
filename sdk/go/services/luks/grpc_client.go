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

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"google.golang.org/grpc"
)

// GRPCClient is a LUKS Service implementation backed by a gRPC
// LUKSServiceClient.
type GRPCClient struct {
	rpc platformv1.LUKSServiceClient
}

// NewGRPCClient returns a LUKS Service backed by the supplied gRPC
// connection.
func NewGRPCClient(conn *grpc.ClientConn) *GRPCClient {
	return &GRPCClient{rpc: platformv1.NewLUKSServiceClient(conn)}
}

// NewGRPCClientFromClient returns a LUKS Service backed by a raw proto client.
func NewGRPCClientFromClient(c platformv1.LUKSServiceClient) *GRPCClient {
	return &GRPCClient{rpc: c}
}

var keyTypeFromProto = map[platformv1.LUKSKeyType]KeyType{
	platformv1.LUKSKeyType_LUKS_KEY_TYPE_UNSPECIFIED: KeyTypeUnspecified,
	platformv1.LUKSKeyType_LUKS_KEY_TYPE_PASSPHRASE:  KeyTypePassphrase,
	platformv1.LUKSKeyType_LUKS_KEY_TYPE_FIDO2:       KeyTypeFIDO2,
	platformv1.LUKSKeyType_LUKS_KEY_TYPE_TPM:         KeyTypeTPM,
	platformv1.LUKSKeyType_LUKS_KEY_TYPE_RECOVERY:    KeyTypeRecovery,
}

func keyslotFromProto(p *platformv1.LUKSKeyslot) Keyslot {
	if p == nil {
		return Keyslot{}
	}
	return Keyslot{
		Slot:     p.GetSlot(),
		Type:     keyTypeFromProto[p.GetType()],
		KeySize:  p.GetKeySize(),
		Priority: p.GetPriority(),
	}
}

// Status proxies Status to the gRPC server.
func (c *GRPCClient) Status(ctx context.Context, req *StatusRequest) (*StatusResponse, error) {
	if req == nil {
		req = &StatusRequest{}
	}
	resp, err := c.rpc.Status(ctx, &platformv1.LUKSStatusRequest{Device: req.Device})
	if err != nil {
		return nil, &ErrStatusFailed{Cause: err}
	}
	return &StatusResponse{
		Device:      resp.GetDevice(),
		IsLUKS:      resp.GetIsLuks(),
		Version:     resp.GetVersion(),
		UUID:        resp.GetUuid(),
		Label:       resp.GetLabel(),
		Cipher:      resp.GetCipher(),
		ActiveSlots: resp.GetActiveSlots(),
	}, nil
}

// ListSlots proxies ListSlots to the gRPC server.
func (c *GRPCClient) ListSlots(ctx context.Context, req *ListSlotsRequest) (*ListSlotsResponse, error) {
	if req == nil {
		req = &ListSlotsRequest{}
	}
	resp, err := c.rpc.ListSlots(ctx, &platformv1.LUKSListSlotsRequest{Device: req.Device})
	if err != nil {
		return nil, &ErrListSlotsFailed{Cause: err}
	}
	out := &ListSlotsResponse{
		Device: resp.GetDevice(),
		Slots:  make([]Keyslot, 0, len(resp.GetSlots())),
	}
	for _, s := range resp.GetSlots() {
		out.Slots = append(out.Slots, keyslotFromProto(s))
	}
	return out, nil
}

// Info proxies Info to the gRPC server.
func (c *GRPCClient) Info(ctx context.Context, req *InfoRequest) (*InfoResponse, error) {
	if req == nil {
		req = &InfoRequest{}
	}
	resp, err := c.rpc.Info(ctx, &platformv1.LUKSInfoRequest{Device: req.Device})
	if err != nil {
		return nil, &ErrInfoFailed{Cause: err}
	}
	out := &InfoResponse{
		Device:       resp.GetDevice(),
		UUID:         resp.GetUuid(),
		Label:        resp.GetLabel(),
		Version:      resp.GetVersion(),
		Cipher:       resp.GetCipher(),
		KeySize:      resp.GetKeySize(),
		SectorSize:   resp.GetSectorSize(),
		MetadataJSON: resp.GetMetadataJson(),
		Slots:        make([]Keyslot, 0, len(resp.GetSlots())),
	}
	for _, s := range resp.GetSlots() {
		out.Slots = append(out.Slots, keyslotFromProto(s))
	}
	return out, nil
}

// EnrollPassphrase proxies EnrollPassphrase to the gRPC server.
func (c *GRPCClient) EnrollPassphrase(ctx context.Context, req *EnrollPassphraseRequest) (*EnrollPassphraseResponse, error) {
	if req == nil {
		req = &EnrollPassphraseRequest{}
	}
	resp, err := c.rpc.EnrollPassphrase(ctx, &platformv1.LUKSEnrollPassphraseRequest{
		Device:             req.Device,
		ExistingPassphrase: req.ExistingPassphrase,
		NewPassphrase:      req.NewPassphrase,
	})
	if err != nil {
		return nil, &ErrEnrollPassphraseFailed{Cause: err}
	}
	return &EnrollPassphraseResponse{Slot: resp.GetSlot()}, nil
}

// EnrollFIDO2 proxies EnrollFIDO2 to the gRPC server.
func (c *GRPCClient) EnrollFIDO2(ctx context.Context, req *EnrollFIDO2Request) (*EnrollFIDO2Response, error) {
	if req == nil {
		req = &EnrollFIDO2Request{}
	}
	resp, err := c.rpc.EnrollFIDO2(ctx, &platformv1.LUKSEnrollFIDO2Request{
		Device:             req.Device,
		ExistingPassphrase: req.ExistingPassphrase,
		CredentialId:       req.CredentialID,
		RequirePin:         req.RequirePIN,
		RequireUv:          req.RequireUV,
	})
	if err != nil {
		return nil, &ErrEnrollFIDO2Failed{Cause: err}
	}
	return &EnrollFIDO2Response{
		Slot:    resp.GetSlot(),
		TokenID: resp.GetTokenId(),
	}, nil
}

// EnrollTPM proxies EnrollTPM to the gRPC server.
func (c *GRPCClient) EnrollTPM(ctx context.Context, req *EnrollTPMRequest) (*EnrollTPMResponse, error) {
	if req == nil {
		req = &EnrollTPMRequest{}
	}
	resp, err := c.rpc.EnrollTPM(ctx, &platformv1.LUKSEnrollTPMRequest{
		Device:             req.Device,
		ExistingPassphrase: req.ExistingPassphrase,
		Pcrs:               req.PCRs,
		Handle:             req.Handle,
	})
	if err != nil {
		return nil, &ErrEnrollTPMFailed{Cause: err}
	}
	return &EnrollTPMResponse{
		Slot:    resp.GetSlot(),
		TokenID: resp.GetTokenId(),
	}, nil
}

// EnrollRecovery proxies EnrollRecovery to the gRPC server.
func (c *GRPCClient) EnrollRecovery(ctx context.Context, req *EnrollRecoveryRequest) (*EnrollRecoveryResponse, error) {
	if req == nil {
		req = &EnrollRecoveryRequest{}
	}
	resp, err := c.rpc.EnrollRecovery(ctx, &platformv1.LUKSEnrollRecoveryRequest{
		Device:             req.Device,
		ExistingPassphrase: req.ExistingPassphrase,
	})
	if err != nil {
		return nil, &ErrEnrollRecoveryFailed{Cause: err}
	}
	return &EnrollRecoveryResponse{
		Slot:        resp.GetSlot(),
		RecoveryKey: resp.GetRecoveryKey(),
	}, nil
}

// RemoveKey proxies RemoveKey to the gRPC server.
func (c *GRPCClient) RemoveKey(ctx context.Context, req *RemoveKeyRequest) (*RemoveKeyResponse, error) {
	if req == nil {
		req = &RemoveKeyRequest{}
	}
	resp, err := c.rpc.RemoveKey(ctx, &platformv1.LUKSRemoveKeyRequest{
		Device: req.Device,
		Slot:   req.Slot,
	})
	if err != nil {
		return nil, &ErrRemoveKeyFailed{Cause: err}
	}
	return &RemoveKeyResponse{Removed: resp.GetRemoved()}, nil
}

// TestUnlock proxies TestUnlock to the gRPC server.
func (c *GRPCClient) TestUnlock(ctx context.Context, req *TestUnlockRequest) (*TestUnlockResponse, error) {
	if req == nil {
		req = &TestUnlockRequest{}
	}
	resp, err := c.rpc.TestUnlock(ctx, &platformv1.LUKSTestUnlockRequest{
		Device: req.Device,
		Slot:   req.Slot,
	})
	if err != nil {
		return nil, &ErrTestUnlockFailed{Cause: err}
	}
	return &TestUnlockResponse{Unlocked: resp.GetUnlocked()}, nil
}

// ChangePassphrase proxies ChangePassphrase to the gRPC server.
func (c *GRPCClient) ChangePassphrase(ctx context.Context, req *ChangePassphraseRequest) (*ChangePassphraseResponse, error) {
	if req == nil {
		req = &ChangePassphraseRequest{}
	}
	resp, err := c.rpc.ChangePassphrase(ctx, &platformv1.LUKSChangePassphraseRequest{
		Device:        req.Device,
		Slot:          req.Slot,
		OldPassphrase: req.OldPassphrase,
		NewPassphrase: req.NewPassphrase,
	})
	if err != nil {
		return nil, &ErrChangePassphraseFailed{Cause: err}
	}
	return &ChangePassphraseResponse{Changed: resp.GetChanged()}, nil
}

// Compile-time interface check.
var _ Service = (*GRPCClient)(nil)
