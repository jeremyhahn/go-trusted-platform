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

// Package quotebindtest fakes the transport and node ends of a quote call
// bound to its connection, for tests of the SDK clients that check the
// bound echo with quotebind.
package quotebindtest

import (
	"context"

	"github.com/google/go-tpm/tpm2"
	xkms "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Bind hands binding to the call's channel-binding option, the way a
// transport adapter does for a connection that exports binding.
func Bind(ctx context.Context, opts []grpc.CallOption, binding []byte) error {
	binder, ok := transport.ChannelBindingFrom(opts)
	if !ok {
		return &ErrUnboundCall{}
	}
	return binder.Bind(ctx, binding)
}

// Quote returns a marshaled TPMS_ATTEST quote carrying
// SHA-256(nonce || binding): what a node quotes for a request that arrived
// on a connection exporting binding.
func Quote(nonce, binding []byte) []byte {
	return tpm2.Marshal(tpm2.TPMSAttest{
		Magic:     tpm2.TPMGeneratedValue,
		Type:      tpm2.TPMSTAttestQuote,
		ExtraData: tpm2.TPM2BData{Buffer: xkms.PeerQualifyingData(nonce, binding)},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(0),
			}}},
			PCRDigest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)},
		}),
	})
}

// ErrUnboundCall is returned by Bind for a call that carries no
// channel-binding option: the client under test sent its quote request
// unbound.
type ErrUnboundCall struct{}

func (e *ErrUnboundCall) Error() string {
	return "quote call sent without a channel-binding option"
}
