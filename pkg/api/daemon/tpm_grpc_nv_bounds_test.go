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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmnv"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// nvBoundsService returns a TPMGRPCService over a TPM with no raw
// transport: a request that passes the NV bounds reaches the transport
// check and comes back Unavailable, one that fails them comes back
// InvalidArgument without touching the TPM.
func nvBoundsService() *TPMGRPCService {
	svc := NewTPMGRPCService(newTPMTestLogger())
	svc.SetTPM2Service(newIDevIDTestTPM())
	return svc
}

func requireCode(t *testing.T, want codes.Code, err error) {
	t.Helper()
	st, ok := status.FromError(err)
	require.True(t, ok, "not a gRPC status: %v", err)
	assert.Equal(t, want, st.Code(), st.Message())
}

func TestTPMGRPC_NVBounds_InRangeReachesTransport(t *testing.T) {
	svc := nvBoundsService()
	ctx := context.Background()
	const index = 0x01C00002

	_, err := svc.ReadNVRAM(ctx, &platformv1.ReadNVRAMRequest{Index: index, Offset: 10, Size: tpmnv.MaxSpan - 10})
	requireCode(t, codes.Unavailable, err)
	_, err = svc.WriteNVRAM(ctx, &platformv1.WriteNVRAMRequest{Index: index, Data: []byte("d")})
	requireCode(t, codes.Unavailable, err)
	_, err = svc.UndefineNVRAM(ctx, &platformv1.UndefineNVRAMRequest{Index: index})
	requireCode(t, codes.Unavailable, err)
	_, err = svc.DefineNVRAM(ctx, &platformv1.DefineNVRAMRequest{Index: index, Size: 32})
	requireCode(t, codes.Unavailable, err)
}

func TestTPMGRPC_NVBounds_IndexOutOfRange(t *testing.T) {
	svc := nvBoundsService()
	ctx := context.Background()
	// A persistent key handle is not an NV index.
	const index = 0x81000001

	_, err := svc.ReadNVRAM(ctx, &platformv1.ReadNVRAMRequest{Index: index})
	requireCode(t, codes.InvalidArgument, err)
	_, err = svc.WriteNVRAM(ctx, &platformv1.WriteNVRAMRequest{Index: index, Data: []byte("d")})
	requireCode(t, codes.InvalidArgument, err)
	_, err = svc.UndefineNVRAM(ctx, &platformv1.UndefineNVRAMRequest{Index: index})
	requireCode(t, codes.InvalidArgument, err)
	_, err = svc.DefineNVRAM(ctx, &platformv1.DefineNVRAMRequest{Index: index, Size: 32})
	requireCode(t, codes.InvalidArgument, err)
}

func TestTPMGRPC_NVBounds_SpanWouldWrap(t *testing.T) {
	svc := nvBoundsService()
	ctx := context.Background()
	const index = 0x01500000

	// A read clamps to the index's DataSize, so a size past the end is
	// not a wrap: it reaches the (absent) transport.
	_, err := svc.ReadNVRAM(ctx, &platformv1.ReadNVRAMRequest{Index: index, Offset: 1, Size: tpmnv.MaxSpan})
	requireCode(t, codes.Unavailable, err)
	_, err = svc.WriteNVRAM(ctx, &platformv1.WriteNVRAMRequest{
		Index:  index,
		Offset: tpmnv.MaxSpan,
		Data:   []byte("x"),
	})
	requireCode(t, codes.InvalidArgument, err)
	_, err = svc.DefineNVRAM(ctx, &platformv1.DefineNVRAMRequest{Index: index, Size: tpmnv.MaxSpan + 1})
	requireCode(t, codes.InvalidArgument, err)
}

// TestMCPServiceProvider_TPMNV_SharesTheNVBounds shows the provider's NV
// tools reach the same tpmnv bounds as gRPC: a non-NV handle is refused,
// and an in-range index gets as far as the (absent) TPM transport.
func TestMCPServiceProvider_TPMNV_SharesTheNVBounds(t *testing.T) {
	ctx := context.Background()
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{TPM2Service: newIDevIDTestTPM()})

	_, err := p.TPMNVRead(ctx, 0x81000001, 0, 0, "")
	requireCode(t, codes.InvalidArgument, err)
	_, err = p.TPMNVWrite(ctx, 0x81000001, []byte("d"), 0, "")
	requireCode(t, codes.InvalidArgument, err)
	_, err = p.TPMNVDelete(ctx, 0x81000001, "")
	requireCode(t, codes.InvalidArgument, err)
	_, err = p.TPMNVWrite(ctx, 0x01500000, []byte("x"), tpmnv.MaxSpan, "")
	requireCode(t, codes.InvalidArgument, err)

	_, err = p.TPMNVRead(ctx, 0x01C00002, 0, 0, "")
	requireCode(t, codes.Unavailable, err)
	_, err = p.TPMNVWrite(ctx, 0x01C00002, []byte("d"), 0, "")
	requireCode(t, codes.Unavailable, err)
	_, err = p.TPMNVDelete(ctx, 0x01C00002, "")
	requireCode(t, codes.Unavailable, err)
}
