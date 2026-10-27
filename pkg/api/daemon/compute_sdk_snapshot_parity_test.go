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

// vmSnapshotSDKVerb drives one VM snapshot verb through the Go SDK compute
// client.
type vmSnapshotSDKVerb struct {
	name  string
	call  func(ctx context.Context, c *sdkcompute.Client, vmID string) error
	typed func(err error) bool
	// fail makes the orchestrator answer the verb with err.
	fail func(orch *computeParityOrchestrator, err error)
	// deletes marks the verb whose REST route is a DELETE.
	deletes bool
}

var vmSnapshotSDKVerbs = []vmSnapshotSDKVerb{
	{
		name: "create",
		call: func(ctx context.Context, c *sdkcompute.Client, vmID string) error {
			_, err := c.CreateSnapshot(ctx, vmID, &platformv1.SnapshotConfig{Name: "nightly", MemorySnapshot: true, DiskSnapshot: true})
			return err
		},
		typed: typedAs[*sdkcompute.ErrCreateSnapshotFailed],
		fail:  func(orch *computeParityOrchestrator, err error) { orch.createSnapshotErr = err },
	},
	{
		name: "restore",
		call: func(ctx context.Context, c *sdkcompute.Client, vmID string) error {
			return c.RestoreSnapshot(ctx, vmID, "nightly")
		},
		typed: typedAs[*sdkcompute.ErrRestoreSnapshotFailed],
		fail:  func(orch *computeParityOrchestrator, err error) { orch.restoreErr = err },
	},
	{
		name: "delete",
		call: func(ctx context.Context, c *sdkcompute.Client, vmID string) error {
			return c.DeleteSnapshot(ctx, vmID, "nightly")
		},
		typed:   typedAs[*sdkcompute.ErrDeleteSnapshotFailed],
		fail:    func(orch *computeParityOrchestrator, err error) { orch.deleteErr = err },
		deletes: true,
	},
	{
		name: "list",
		call: func(ctx context.Context, c *sdkcompute.Client, vmID string) error {
			_, err := c.ListSnapshots(ctx, vmID)
			return err
		},
		typed: typedAs[*sdkcompute.ErrListSnapshotsFailed],
		fail:  func(orch *computeParityOrchestrator, err error) { orch.listErr = err },
	},
}

func TestVMSnapshotSDKParity_CreateThenList(t *testing.T) {
	for _, transport := range vmSDKTransports {
		t.Run(transport.name, func(t *testing.T) {
			provider, svc, _ := seededVMPair()
			client := transport.dial(t, provider, svc)
			ctx := context.Background()

			created, err := client.CreateSnapshot(ctx, "vm-1", &platformv1.SnapshotConfig{Name: "nightly", MemorySnapshot: true, DiskSnapshot: true})
			require.NoError(t, err)
			assert.Equal(t, "nightly", created.GetId())
			assert.Equal(t, "vm-1", created.GetVmId())

			listed, err := client.ListSnapshots(ctx, "vm-1")
			require.NoError(t, err)
			require.Len(t, listed, 1)
			assert.Equal(t, "nightly", listed[0].GetId())

			got, err := client.GetSnapshot(ctx, "vm-1", "nightly")
			require.NoError(t, err)
			assert.Equal(t, "nightly", got.GetId())
			assert.Equal(t, "vm-1", got.GetVmId())
		})
	}
}

func TestVMSnapshotSDKParity_GetUnknownSnapshot(t *testing.T) {
	for _, transport := range vmSDKTransports {
		t.Run(transport.name, func(t *testing.T) {
			provider, svc, _ := seededVMPair()
			client := transport.dial(t, provider, svc)

			_, err := client.GetSnapshot(context.Background(), "vm-1", "never-taken")
			assert.True(t, typedAs[*sdkcompute.ErrGetSnapshotFailed](err), "err = %T, want *ErrGetSnapshotFailed", err)
			assert.Equal(t, codes.NotFound, status.Code(err), "err = %v", err)
		})
	}
}

func TestVMSnapshotSDKParity_RunsTheVerb(t *testing.T) {
	for _, transport := range vmSDKTransports {
		for _, verb := range vmSnapshotSDKVerbs {
			t.Run(transport.name+" "+verb.name, func(t *testing.T) {
				provider, svc, _ := seededVMPair()
				client := transport.dial(t, provider, svc)

				require.NoError(t, verb.call(context.Background(), client, "vm-1"))
			})
		}
	}
}

func TestVMSnapshotSDKParity_UnknownVM(t *testing.T) {
	notFound := &compute.SentinelCauseError{Sentinel: compute.ErrInstanceNotFound, Cause: &compute.MessageError{Msg: "no such vm"}}
	for _, transport := range vmSDKTransports {
		for _, verb := range vmSnapshotSDKVerbs {
			t.Run(transport.name+" "+verb.name, func(t *testing.T) {
				provider, svc, orch := seededVMPair()
				verb.fail(orch, notFound)
				client := transport.dial(t, provider, svc)

				err := verb.call(context.Background(), client, "vm-missing")
				assert.True(t, verb.typed(err), "err = %T, want the client's typed %s error", err, verb.name)
				assert.Equal(t, codes.NotFound, status.Code(err), "err = %v", err)
			})
		}
	}
}

func TestVMSnapshotSDKParity_VMNotRunning(t *testing.T) {
	notRunning := &compute.SentinelCauseError{Sentinel: compute.ErrInstanceNotRunning, Cause: &compute.MessageError{Msg: "vm stopped"}}
	for _, transport := range vmSDKTransports {
		for _, verb := range vmSnapshotSDKVerbs {
			t.Run(transport.name+" "+verb.name, func(t *testing.T) {
				provider, svc, orch := seededVMPair()
				verb.fail(orch, notRunning)
				client := transport.dial(t, provider, svc)

				err := verb.call(context.Background(), client, "vm-1")
				assert.True(t, verb.typed(err), "err = %T, want the client's typed %s error", err, verb.name)
				assert.Equal(t, transport.wrongStateOf(verb.deletes), status.Code(err), "err = %v", err)
			})
		}
	}
}

// A missing VM id is InvalidArgument for every snapshot and attestation verb
// on every transport, and never reaches the orchestrator.
func TestVMSnapshotAttestSDKParity_MissingVMID(t *testing.T) {
	verbs := append(append([]vmSnapshotSDKVerb{}, vmSnapshotSDKVerbs...), vmAttestSDKVerbs...)
	for _, transport := range vmSDKTransports {
		for _, verb := range verbs {
			t.Run(transport.name+" "+verb.name, func(t *testing.T) {
				provider, svc, orch := seededVMPair()
				verb.fail(orch, &compute.MessageError{Msg: "the orchestrator was reached"})
				client := transport.dial(t, provider, svc)

				err := verb.call(context.Background(), client, "")
				assert.Equal(t, codes.InvalidArgument, status.Code(err), "err = %v", err)
			})
		}
	}
}
