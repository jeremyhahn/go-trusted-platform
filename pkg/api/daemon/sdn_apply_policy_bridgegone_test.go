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

// The constraint matches sdn_apply_policy_enforce_test.go, whose fixtures
// (replacingOVS, twoRulePolicyConfig) are used here.

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// goneBridgeOVS is a replacingOVS whose strict deletes fail with
// ErrBridgeNotFound on a bridge the switch no longer has.
type goneBridgeOVS struct {
	*replacingOVS
}

func (f *goneBridgeOVS) DeleteFlowStrict(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	f.mu.RLock()
	_, ok := f.bridges[bridgeName]
	f.mu.RUnlock()
	if !ok {
		return fmt.Errorf("bridge %s: %w", bridgeName, ovs.ErrBridgeNotFound)
	}
	return f.replacingOVS.DeleteFlowStrict(ctx, bridgeName, flow)
}

// newGoneBridgeFixture applies twoRulePolicyConfig as p1 on br0 and then
// deletes br0 through the service.
func newGoneBridgeFixture(t *testing.T) (*SDNService, *goneBridgeOVS) {
	t.Helper()
	fake := &goneBridgeOVS{replacingOVS: &replacingOVS{MockOVSClientInterface: NewMockOVSClientInterface()}}
	fake.AddBridgeToMock("br0", &ovs.Bridge{UUID: "uuid-br0", Name: "br0"})
	svc, err := NewSDNService("", WithOVSClient(fake))
	require.NoError(t, err)

	ctx := context.Background()
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.NoError(t, err)
	require.NotEmpty(t, fake.matches(t, "br0"))
	_, err = svc.DeleteBridge(ctx, &platformv1.DeleteBridgeRequest{Id: "br0"})
	require.NoError(t, err)
	return svc, fake
}

func TestSDNService_DeletePolicy_AfterBridgeDeleteRemovesTheRecord(t *testing.T) {
	svc, _ := newGoneBridgeFixture(t)
	ctx := context.Background()

	_, err := svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "p1"})
	require.NoError(t, err)
	_, err = svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: "p1"})
	assert.Equal(t, codes.NotFound, status.Code(err), "err = %v", err)
}

func TestSDNService_DeletePolicy_BridgeListFailureStaysInternal(t *testing.T) {
	svc, fake := newGoneBridgeFixture(t)
	ctx := context.Background()
	fake.listBridgesErr = errInjectedOVS

	_, err := svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "p1"})
	assert.Equal(t, codes.Internal, status.Code(err), "err = %v", err)
	_, err = svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: "p1"})
	assert.NoError(t, err, "the record stays when the bridge's absence is not confirmed")
}
