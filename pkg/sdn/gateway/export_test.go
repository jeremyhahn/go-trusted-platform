package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// NewTestRuntime returns the fake datapath runtime the in-package tests use,
// with the load balancer's group client, for the external tests that run a
// gateway as a supervised child.
func NewTestRuntime() *GatewayRuntime {
	runtime := newTestRuntime()
	runtime.Groups = newFakeGroupClient()
	return runtime
}

// TestBridge is a fake OVS bridge several runtimes share (bridge_test.go).
type TestBridge = testBridge

// NewTestBridge returns an empty shared fake bridge.
func NewTestBridge() *TestBridge { return newTestBridge() }

// NewTestRuntimeOn returns a fresh runtime that programs bridge, so each
// supervised child in a test starts over the bridge its predecessor left.
func NewTestRuntimeOn(bridge *TestBridge) *GatewayRuntime {
	runtime := newTestRuntime()
	runtime.Controller = &testController{b: bridge}
	runtime.OVS = bridge
	runtime.Groups = bridge
	return runtime
}

// TwoLaptopVPNSection is the vpn section enrolling tenant-a's laptop-1 and
// laptop-2.
func TwoLaptopVPNSection() *gwstate.DesiredVPN {
	section := laptopSection()
	section.Peers = append(section.Peers,
		gwstate.DesiredVPNPeer{TenantID: "tenant-a", DeviceID: "laptop-2", Zones: []string{"management"}})
	return section
}

// NewDeleteRefusingLeaseControl is a lease control plane that records lease-1
// (laptop-1) and lease-2 (laptop-2) and refuses every DELETE. It is never
// changed after it is built, so the goroutines of the children sharing it
// only read it.
func NewDeleteRefusingLeaseControl() VPNLeaseControl {
	second := recordedLease()
	second.ID = "lease-2"
	second.DeviceID = "laptop-2"
	second.Address = "100.64.0.3/32"
	second.ClientCertificateSHA256 = make([]byte, 32)
	second.ClientCertificateSHA256[0] = 2
	section := TwoLaptopVPNSection()
	section.Leases = []gwstate.DesiredVPNLease{recordedLease(), second}
	return &fakeLeaseControl{
		desired:   &gwstate.DesiredConfig{GatewayID: "vpn-gw", VPN: section},
		deleteErr: errors.New("control plane returned 503"),
	}
}

// NewVPNChildGateway is a gateway hosting only the management VPN, over
// control and the revocation journal at journalPath, as the vpn child is.
func NewVPNChildGateway(t *testing.T, control VPNLeaseControl, journalPath string) *Gateway {
	t.Helper()
	return projectedRigOver(t, control, NewRevocationJournal(journalPath)).gw
}

// RevokeVPNLease revokes a lease of g's running management VPN as an
// operator would.
func RevokeVPNLease(ctx context.Context, g *Gateway, id string) error {
	g.vpnMu.Lock()
	backend := g.vpn
	g.vpnMu.Unlock()
	if backend == nil {
		return &ErrServiceUnavailable{Service: ServiceManagementVPN, Reason: "the management VPN is not running"}
	}
	return backend.svc.Revoke(ctx, vpn.LeaseID(id), vpn.RevokeOperator)
}

// PendingVPNRevocations lists the lease IDs the revocation journal at path
// still holds.
func PendingVPNRevocations(path string) ([]string, error) {
	pending, err := NewRevocationJournal(path).load()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(pending))
	for id := range pending {
		ids = append(ids, string(id))
	}
	return ids, nil
}
