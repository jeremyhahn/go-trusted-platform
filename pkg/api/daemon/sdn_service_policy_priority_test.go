package daemon

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// countSwitchCalls makes every AddFlow and DeleteFlowStrict on client
// count into the returned pointers.
func countSwitchCalls(client *switchModelClient) (adds, deletes *int) {
	adds, deletes = new(int), new(int)
	client.mu.Lock()
	client.addHook = func(*ovs.FlowMod) error { *adds++; return nil }
	client.deleteHook = func(*ovs.FlowMod) error { *deletes++; return nil }
	client.mu.Unlock()
	return adds, deletes
}

func TestSDNService_ApplyPolicy_RefusesRulePriorityOutsideUint16(t *testing.T) {
	for _, prio := range []int32{65536, 65636, -1} {
		svc, client := newSwitchModelSDNService(t)
		adds, deletes := countSwitchCalls(client)

		rule := allowRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 80})
		rule.Priority = prio
		if _, err := svc.ApplyPolicy(context.Background(), denyPolicy("big", rule)); err == nil {
			t.Fatalf("rule priority %d: apply succeeded", prio)
		}
		client.mu.Lock()
		a, d := *adds, *deletes
		client.mu.Unlock()
		if a != 0 || d != 0 {
			t.Fatalf("rule priority %d: %d adds and %d deletes reached the switch, want none", prio, a, d)
		}
	}
}

func TestSDNService_ApplyPolicy_RefusesPolicyPriorityOutsideUint16(t *testing.T) {
	svc, client := newSwitchModelSDNService(t)
	adds, deletes := countSwitchCalls(client)

	req := denyPolicy("big", allowRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 80}))
	req.Config.Priority = 70000
	if _, err := svc.ApplyPolicy(context.Background(), req); err == nil {
		t.Fatal("policy priority 70000: apply succeeded")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if *adds != 0 || *deletes != 0 {
		t.Fatalf("%d adds and %d deletes reached the switch, want none", *adds, *deletes)
	}
}

// An allow at priority 65636 truncates to 100 on the switch and would
// replace the priority-100 deny under a different rollback key; the update
// must be refused before it touches the deny.
func TestSDNService_ApplyPolicy_WrappingPriorityKeepsTheOldDeny(t *testing.T) {
	svc, client := newSwitchModelSDNService(t)
	ctx := context.Background()

	web := &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 80}
	deny := denyRule("r1", web)
	denyReq := denyPolicy("deny-web", deny)
	denyReq.PolicyId = "p1"
	if _, err := svc.ApplyPolicy(ctx, denyReq); err != nil {
		t.Fatalf("apply deny: %v", err)
	}
	denyFlow, err := svc.policyRuleToFlowMod(deny, 100)
	if err != nil {
		t.Fatalf("translate deny: %v", err)
	}
	denyActions, ok := client.entry(denyFlow.Match)
	if !ok {
		t.Fatalf("deny flow %q not installed", denyFlow.Match)
	}
	adds, deletes := countSwitchCalls(client)

	wrap := allowRule("r2", web)
	wrap.Priority = 65636
	broken := allowRule("r3", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 443})
	if _, err := svc.ApplyPolicy(ctx, denyPolicy("wrap", wrap, broken)); err == nil {
		t.Fatal("apply with priority 65636 succeeded")
	}
	client.mu.Lock()
	a, d := *adds, *deletes
	client.mu.Unlock()
	if a != 0 || d != 0 {
		t.Fatalf("%d adds and %d deletes reached the switch, want none", a, d)
	}
	if got, ok := client.entry(denyFlow.Match); !ok || got != denyActions {
		t.Fatalf("deny entry %q = %q (present %v), want %q", denyFlow.Match, got, ok, denyActions)
	}
}
