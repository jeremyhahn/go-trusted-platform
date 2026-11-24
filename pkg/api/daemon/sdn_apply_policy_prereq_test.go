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

// The constraint matches quic_sdn_handlers_test.go, which defines the
// MockOVSClientInterface and newTestSDNServiceWithMock helpers used here.

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestSDNService_PolicyRuleFlowMod_CarriesPrerequisites pins the match a
// policy rule installs: every address, protocol or port term carries the
// OpenFlow prerequisites (dl_type, nw_proto) a switch requires.
func TestSDNService_PolicyRuleFlowMod_CarriesPrerequisites(t *testing.T) {
	svc, _ := newEnforcePolicyFixture(t)

	tests := []struct {
		name  string
		match *platformv1.PolicyRuleMatch
		want  string
	}{
		{"ipv4 source", &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.10"}, "dl_type=0x0800,nw_src=192.0.2.10"},
		{"tcp destination port", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationIp: "198.51.100.5", DestinationPort: 22},
			"dl_type=0x0800,nw_proto=6,nw_dst=198.51.100.5,tp_dst=22"},
		{"udp source port", &platformv1.PolicyRuleMatch{Protocol: "udp", SourcePort: 53}, "dl_type=0x0800,nw_proto=17,tp_src=53"},
		{"icmpv6", &platformv1.PolicyRuleMatch{Protocol: "icmpv6"}, "dl_type=0x86dd,nw_proto=58"},
		{"ipv6 source", &platformv1.PolicyRuleMatch{SourceIp: "2001:db8::1"}, "dl_type=0x86dd,ipv6_src=2001:db8::1"},
		{"tcp over ipv6", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationIp: "2001:db8::5", DestinationPort: 443},
			"dl_type=0x86dd,nw_proto=6,ipv6_dst=2001:db8::5,tp_dst=443"},
		{"vlan only", &platformv1.PolicyRuleMatch{VlanId: 100}, "dl_vlan=100"},
		{"no match", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &platformv1.PolicyRule{
				RuleId: "r1",
				Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW,
				Match:  tt.match,
			}
			mod, err := svc.policyRuleToFlowMod(rule, 100)
			require.NoError(t, err)
			require.NotNil(t, mod)
			assert.Equal(t, tt.want, mod.Match)
			assert.NoError(t, ovs.ValidateFlowMod(mod))
		})
	}
}

// TestSDNService_ApplyPolicy_RefusesRuleWithoutPrerequisites checks that a
// rule whose match cannot carry its OpenFlow prerequisites is refused with
// InvalidArgument before any flow is installed or the policy is stored.
func TestSDNService_ApplyPolicy_RefusesRuleWithoutPrerequisites(t *testing.T) {
	tests := []struct {
		name  string
		match *platformv1.PolicyRuleMatch
	}{
		{"port without protocol", &platformv1.PolicyRuleMatch{DestinationPort: 22}},
		{"port under icmp", &platformv1.PolicyRuleMatch{Protocol: "icmp", DestinationPort: 22}},
		{"port under sctp", &platformv1.PolicyRuleMatch{Protocol: "sctp", SourcePort: 9}},
		{"icmp with ipv6 address", &platformv1.PolicyRuleMatch{Protocol: "icmp", SourceIp: "2001:db8::1"}},
		{"icmpv6 with ipv4 address", &platformv1.PolicyRuleMatch{Protocol: "icmpv6", SourceIp: "192.0.2.10"}},
		{"mixed address families", &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.10", DestinationIp: "2001:db8::5"}},
		{"unknown protocol", &platformv1.PolicyRuleMatch{Protocol: "bogus"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mockOVS := newEnforcePolicyFixture(t)
			cfg := &platformv1.PolicyConfig{
				Name:     "web",
				Priority: 100,
				Enabled:  true,
				Rules: []*platformv1.PolicyRule{
					{RuleId: "ok", Priority: 90, Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW,
						Match: &platformv1.PolicyRuleMatch{SourceIp: "203.0.113.7"}},
					{RuleId: "bad-rule", Priority: 100, Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
						Match: tt.match},
				},
				Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
			}

			_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{Config: cfg})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Contains(t, status.Convert(err).Message(), `"bad-rule"`)
			requireNoFlows(t, mockOVS, "br0")

			svc.mu.RLock()
			defer svc.mu.RUnlock()
			assert.Empty(t, svc.policies)
		})
	}
}
