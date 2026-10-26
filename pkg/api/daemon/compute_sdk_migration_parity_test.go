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

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkcompute "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// dialMigrationReceiver connects an SDK compute client over one transport
// to daemon handlers backed by recv.
func dialMigrationReceiver(t *testing.T, transport vmSDKTransport, recv *migrationReceiverOrchestrator) *sdkcompute.Client {
	t.Helper()
	return transport.dial(t, newMigrationParityProvider(recv), newMigrationReceiverService(recv))
}

// TestVMMigrationSDKParity_PrepareThenFinalize runs the destination half of a
// migration through the SDK on every transport.
func TestVMMigrationSDKParity_PrepareThenFinalize(t *testing.T) {
	for _, transport := range vmSDKTransports {
		t.Run(transport.name, func(t *testing.T) {
			recv := newParityReceiver()
			client := dialMigrationReceiver(t, transport, recv)

			resp, err := client.PrepareMigration(context.Background(), &platformv1.PrepareMigrationRequest{
				VmName: "guest", Mode: "live",
				Spec: &platformv1.VMMigrationSpec{MemoryMb: 2048, Cpus: 2},
			})
			require.NoError(t, err)
			assert.Equal(t, "recv-1", resp.GetReceiverId())
			assert.Equal(t, int32(49200), resp.GetPort())
			assert.Equal(t, "dest.example", resp.GetTlsHostname())
			assert.Equal(t, "guest", recv.recordedSpec().VMName)

			require.NoError(t, client.FinalizeMigration(context.Background(), resp.GetReceiverId(), true))
			assert.Equal(t, "recv-1", recv.recordedReceiverID())
			assert.True(t, recv.recordedCommit())
		})
	}
}

// TestVMMigrationSDKParity_PrepareWithoutSpec: every transport refuses a
// prepare with no guest description as InvalidArgument.
func TestVMMigrationSDKParity_PrepareWithoutSpec(t *testing.T) {
	for _, transport := range vmSDKTransports {
		t.Run(transport.name, func(t *testing.T) {
			client := dialMigrationReceiver(t, transport, newParityReceiver())

			_, err := client.PrepareMigration(context.Background(), &platformv1.PrepareMigrationRequest{VmName: "guest"})
			assert.True(t, typedAs[*sdkcompute.ErrPrepareMigrationFailed](err), "err = %T, want *ErrPrepareMigrationFailed", err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err), "err = %v", err)
		})
	}
}

// TestVMMigrationSDKParity_FinalizeUnknownReceiver: every transport reports a
// receiver the destination does not hold as NotFound.
func TestVMMigrationSDKParity_FinalizeUnknownReceiver(t *testing.T) {
	for _, transport := range vmSDKTransports {
		t.Run(transport.name, func(t *testing.T) {
			recv := newParityReceiver()
			recv.finalizeErr = compute.ErrReceiverNotFound
			client := dialMigrationReceiver(t, transport, recv)

			err := client.FinalizeMigration(context.Background(), "nope", false)
			assert.True(t, typedAs[*sdkcompute.ErrFinalizeMigrationFailed](err), "err = %T, want *ErrFinalizeMigrationFailed", err)
			assert.Equal(t, codes.NotFound, status.Code(err), "err = %v", err)
		})
	}
}
