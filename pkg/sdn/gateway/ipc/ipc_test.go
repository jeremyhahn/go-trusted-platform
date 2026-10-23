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

//go:build linux

package ipc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
)

// fakeNode is a child gateway with scripted state, reports and apply
// outcome.
type fakeNode struct {
	state    gateway.GatewayState
	reports  []gateway.ServiceReport
	applyErr error
	applied  *gwstate.DesiredConfig
	desired  gwstate.DesiredConfigState
}

func (f *fakeNode) GetState() gateway.GatewayState          { return f.state }
func (f *fakeNode) ServiceReports() []gateway.ServiceReport { return f.reports }
func (f *fakeNode) Snapshot() *gwstate.Snapshot {
	return &gwstate.Snapshot{GatewayID: "gw-test", Mode: "firewall,nat"}
}
func (f *fakeNode) Apply(_ context.Context, desired *gwstate.DesiredConfig) error {
	f.applied = desired
	if f.applyErr != nil {
		f.desired.LastError = f.applyErr.Error()
		return f.applyErr
	}
	f.desired.Version = desired.EffectiveVersion()
	f.desired.LastError = ""
	return nil
}
func (f *fakeNode) DesiredConfigState() gwstate.DesiredConfigState { return f.desired }

// serve starts a server for node under policy on a socket in a temp dir
// and returns a connected client. Both are torn down with the test.
func serve(t *testing.T, node Node, policy Policy) (*Server, *Client) {
	t.Helper()
	// Unix socket paths are limited to ~108 bytes; t.TempDir can exceed that.
	dir, err := os.MkdirTemp("/tmp", "gwipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "p.sock")

	srv := NewServer(node, policy)
	if err := srv.Listen(path, 0o600, -1); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()
	t.Cleanup(func() {
		srv.Stop()
		if err := <-served; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	})

	client, err := Dial(path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return srv, client
}

func creds(uid uint32) peercred.UnixCredentials {
	return peercred.UnixCredentials{PID: 1, UID: uid, GID: uid}
}

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// The running process is the caller here, so its own uid is what the
// kernel reports; a policy admitting it exercises the allow path.
func selfPolicy() Policy {
	uid := uint32(os.Getuid())
	return Policy{ControlUIDs: []uint32{uid}, DatapathUIDs: []uint32{uid}}
}

func TestStatus_ReportsStateServicesAndStartError(t *testing.T) {
	node := &fakeNode{
		state: gateway.GatewayStateError,
		reports: []gateway.ServiceReport{
			{Name: gateway.ServiceFirewall, Active: true},
			{Name: gateway.ServiceNAT, Active: false, Health: errors.New("nat: applier lost netlink")},
		},
	}
	srv, client := serve(t, node, selfPolicy())
	srv.SetStartError(errors.New("firewall: bridge br-fabric not provisioned"))

	resp, err := client.Status(testContext(t))
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if resp.GetState() != ipcv1.ProcessState_PROCESS_STATE_ERROR {
		t.Fatalf("state = %v, want ERROR", resp.GetState())
	}
	if resp.GetStartError() != "firewall: bridge br-fabric not provisioned" {
		t.Fatalf("start_error = %q", resp.GetStartError())
	}
	if len(resp.GetServices()) != 2 {
		t.Fatalf("services = %d, want 2", len(resp.GetServices()))
	}
	fw, nat := resp.GetServices()[0], resp.GetServices()[1]
	if fw.GetName() != gateway.ServiceFirewall || !fw.GetActive() || !fw.GetHealthy() || fw.GetHealthError() != "" {
		t.Fatalf("firewall status = %v", fw)
	}
	if nat.GetName() != gateway.ServiceNAT || nat.GetActive() || nat.GetHealthy() || nat.GetHealthError() != "nat: applier lost netlink" {
		t.Fatalf("nat status = %v", nat)
	}

	srv.SetStartError(nil)
	resp, err = client.Status(testContext(t))
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if resp.GetStartError() != "" {
		t.Fatalf("start_error after clear = %q", resp.GetStartError())
	}
}

func TestSnapshot_RoundTripsTheDocument(t *testing.T) {
	_, client := serve(t, &fakeNode{state: gateway.GatewayStateRunning}, selfPolicy())
	snap, err := client.Snapshot(testContext(t))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.GatewayID != "gw-test" || snap.Mode != "firewall,nat" {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestApplyDesired_AppliesThroughTheNodeAndReturnsState(t *testing.T) {
	node := &fakeNode{state: gateway.GatewayStateRunning}
	_, client := serve(t, node, selfPolicy())

	desired := &gwstate.DesiredConfig{GatewayID: "gw-test", Version: "v7", NAT: &gwstate.DesiredNAT{}}
	state, err := client.ApplyDesired(testContext(t), desired)
	if err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if node.applied == nil || node.applied.Version != "v7" || node.applied.NAT == nil {
		t.Fatalf("node applied %+v", node.applied)
	}
	if state.Version != "v7" || state.LastError != "" {
		t.Fatalf("state = %+v", state)
	}
}

func TestApplyDesired_CarriesTheApplyErrorBesideTheState(t *testing.T) {
	node := &fakeNode{state: gateway.GatewayStateRunning, applyErr: errors.New("load balancer not enabled")}
	_, client := serve(t, node, selfPolicy())

	state, err := client.ApplyDesired(testContext(t), &gwstate.DesiredConfig{GatewayID: "gw-test", Version: "v8"})
	var remote *ErrRemoteApply
	if !errors.As(err, &remote) {
		t.Fatalf("err = %v, want *ErrRemoteApply", err)
	}
	if remote.Message != "load balancer not enabled" {
		t.Fatalf("remote message = %q", remote.Message)
	}
	if state.LastError != "load balancer not enabled" {
		t.Fatalf("state = %+v, want the child's LastError", state)
	}
}

// fakeVPNPlanes records the peer RPCs it is handed and answers with a
// scripted refusal.
type fakeVPNPlanes struct {
	refusal   *ipcv1.VPNPeerRefusal
	installed *ipcv1.VPNPeer
	removed   *ipcv1.RemoveVPNPeerRequest
}

func (f *fakeVPNPlanes) InstallVPNPeer(_ context.Context, req *ipcv1.InstallVPNPeerRequest) *ipcv1.InstallVPNPeerResponse {
	f.installed = req.GetPeer()
	return &ipcv1.InstallVPNPeerResponse{Refusal: f.refusal}
}

func (f *fakeVPNPlanes) RemoveVPNPeer(_ context.Context, req *ipcv1.RemoveVPNPeerRequest) *ipcv1.RemoveVPNPeerResponse {
	f.removed = req
	return &ipcv1.RemoveVPNPeerResponse{Refusal: f.refusal}
}

func TestVPNPeer_ForwardsToTheHostedPlanes(t *testing.T) {
	srv, client := serve(t, &fakeNode{state: gateway.GatewayStateRunning}, selfPolicy())
	planes := &fakeVPNPlanes{}
	srv.SetVPNPlanes(planes)

	peer := &ipcv1.VPNPeer{LeaseId: "l1", DataPlane: "masque", Address: "100.64.0.7/32", ClientCertificateSha256: []byte{1, 2, 3}}
	resp, err := client.InstallVPNPeer(testContext(t), &ipcv1.InstallVPNPeerRequest{Peer: peer})
	if err != nil {
		t.Fatalf("InstallVPNPeer: %v", err)
	}
	if resp.GetRefusal() != nil {
		t.Fatalf("refusal = %v, want none", resp.GetRefusal())
	}
	if planes.installed.GetLeaseId() != "l1" || planes.installed.GetAddress() != "100.64.0.7/32" ||
		len(planes.installed.GetClientCertificateSha256()) != 3 {
		t.Fatalf("planes saw %v", planes.installed)
	}

	removed, err := client.RemoveVPNPeer(testContext(t), &ipcv1.RemoveVPNPeerRequest{DataPlane: "masque", LeaseId: "l1"})
	if err != nil {
		t.Fatalf("RemoveVPNPeer: %v", err)
	}
	if removed.GetRefusal() != nil || planes.removed.GetLeaseId() != "l1" || planes.removed.GetDataPlane() != "masque" {
		t.Fatalf("remove = %v, planes saw %v", removed.GetRefusal(), planes.removed)
	}
}

func TestVPNPeer_CarriesThePlanesRefusal(t *testing.T) {
	srv, client := serve(t, &fakeNode{state: gateway.GatewayStateRunning}, selfPolicy())
	srv.SetVPNPlanes(&fakeVPNPlanes{refusal: &ipcv1.VPNPeerRefusal{
		Class:           ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_PEER_CONFLICT,
		ExistingLeaseId: "l0",
		Reason:          "the address is already bound",
	}})

	resp, err := client.InstallVPNPeer(testContext(t), &ipcv1.InstallVPNPeerRequest{Peer: &ipcv1.VPNPeer{LeaseId: "l1"}})
	if err != nil {
		t.Fatalf("a refusal must not be an RPC error: %v", err)
	}
	refusal := resp.GetRefusal()
	if refusal.GetClass() != ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_PEER_CONFLICT ||
		refusal.GetExistingLeaseId() != "l0" || refusal.GetReason() != "the address is already bound" {
		t.Fatalf("refusal = %v", refusal)
	}
}

func TestVPNPeer_RefusedWhenTheProcessHostsNoPlanes(t *testing.T) {
	srv, client := serve(t, &fakeNode{state: gateway.GatewayStateRunning}, selfPolicy())
	unavailable := ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_UNAVAILABLE

	install, err := client.InstallVPNPeer(testContext(t), &ipcv1.InstallVPNPeerRequest{Peer: &ipcv1.VPNPeer{LeaseId: "l1"}})
	if err != nil || install.GetRefusal().GetClass() != unavailable {
		t.Fatalf("install with no planes = %v, %v; want an UNAVAILABLE refusal", install.GetRefusal(), err)
	}
	remove, err := client.RemoveVPNPeer(testContext(t), &ipcv1.RemoveVPNPeerRequest{LeaseId: "l1"})
	if err != nil || remove.GetRefusal().GetClass() != unavailable {
		t.Fatalf("remove with no planes = %v, %v; want an UNAVAILABLE refusal", remove.GetRefusal(), err)
	}

	// Withdrawn planes refuse again.
	planes := &fakeVPNPlanes{}
	srv.SetVPNPlanes(planes)
	srv.SetVPNPlanes(nil)
	install, err = client.InstallVPNPeer(testContext(t), &ipcv1.InstallVPNPeerRequest{Peer: &ipcv1.VPNPeer{LeaseId: "l1"}})
	if err != nil || install.GetRefusal().GetClass() != unavailable || planes.installed != nil {
		t.Fatalf("install after withdrawal = %v, %v; planes saw %v", install.GetRefusal(), err, planes.installed)
	}
}

func TestPolicy_DeniesAnUnadmittedUIDOnEveryService(t *testing.T) {
	// No caller is uid 4294967000, so both services must refuse us.
	policy := Policy{ControlUIDs: []uint32{4294967000}, DatapathUIDs: []uint32{4294967000}}
	_, client := serve(t, &fakeNode{state: gateway.GatewayStateRunning}, policy)

	_, err := client.Status(testContext(t))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Status err = %v, want PermissionDenied", err)
	}
	_, err = client.ApplyDesired(testContext(t), &gwstate.DesiredConfig{GatewayID: "gw-test"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ApplyDesired err = %v, want PermissionDenied", err)
	}
	_, err = client.InstallVPNPeer(testContext(t), &ipcv1.InstallVPNPeerRequest{Peer: &ipcv1.VPNPeer{LeaseId: "l1"}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("InstallVPNPeer err = %v, want PermissionDenied", err)
	}
	_, err = client.RemoveVPNPeer(testContext(t), &ipcv1.RemoveVPNPeerRequest{LeaseId: "l1"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("RemoveVPNPeer err = %v, want PermissionDenied", err)
	}
}

func TestPolicy_TheParserUIDReachesOnlyTheVPNPeerMethods(t *testing.T) {
	// Control admits a uid nobody has; the datapath list admits us, as it
	// admits the parser class. The VPN peer methods must answer while
	// Status and ApplyDesired, the supervisor's alone, are refused: a
	// compromised parser must not replace the firewall's desired document.
	policy := Policy{ControlUIDs: []uint32{4294967000}, DatapathUIDs: []uint32{uint32(os.Getuid())}}
	_, client := serve(t, &fakeNode{state: gateway.GatewayStateRunning}, policy)

	if _, err := client.Status(testContext(t)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Status err = %v, want PermissionDenied", err)
	}
	if _, err := client.ApplyDesired(testContext(t), &gwstate.DesiredConfig{GatewayID: "gw-test"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ApplyDesired err = %v, want PermissionDenied", err)
	}
	if _, err := client.InstallVPNPeer(testContext(t), &ipcv1.InstallVPNPeerRequest{Peer: &ipcv1.VPNPeer{LeaseId: "l1"}}); err != nil {
		t.Fatalf("InstallVPNPeer: %v", err)
	}
	if _, err := client.RemoveVPNPeer(testContext(t), &ipcv1.RemoveVPNPeerRequest{LeaseId: "l1"}); err != nil {
		t.Fatalf("RemoveVPNPeer: %v", err)
	}
}

func TestPolicyAdmit_TableAndUnknownMethod(t *testing.T) {
	p := Policy{DatapathUIDs: []uint32{1001}}
	cases := []struct {
		method string
		parser bool
	}{
		{ipcv1.ProcessControlService_Status_FullMethodName, false},
		{ipcv1.ProcessControlService_Snapshot_FullMethodName, false},
		{ipcv1.DatapathService_ApplyDesired_FullMethodName, false},
		{ipcv1.DatapathService_InstallVPNPeer_FullMethodName, true},
		{ipcv1.DatapathService_RemoveVPNPeer_FullMethodName, true},
	}
	for _, tc := range cases {
		if err := p.admit(tc.method, creds(0)); err != nil {
			t.Fatalf("root on %s: %v", tc.method, err)
		}
		var denied *ErrPeerDenied
		if err := p.admit(tc.method, creds(1002)); !errors.As(err, &denied) || denied.Method != tc.method {
			t.Fatalf("other on %s = %v, want ErrPeerDenied naming the method", tc.method, err)
		}
		err := p.admit(tc.method, creds(1001))
		if tc.parser && err != nil {
			t.Fatalf("parser on %s: %v", tc.method, err)
		}
		if !tc.parser && (!errors.As(err, &denied) || denied.UID != 1001) {
			t.Fatalf("parser on %s = %v, want ErrPeerDenied", tc.method, err)
		}
	}
	var unknown *ErrUnknownService
	for _, method := range []string{"/gatewayd.ipc.v1.DatapathService/Nothing", "/gatewayd.ipc.v1.Nothing/Status", ""} {
		if err := p.admit(method, creds(0)); !errors.As(err, &unknown) || unknown.Method != method {
			t.Fatalf("admit(%q) = %v, want ErrUnknownService", method, err)
		}
	}
}

func TestPolicy_EveryContractMethodIsPlaced(t *testing.T) {
	// A method added to ipc.proto without a policy entry would be refused
	// to everyone, the supervisor included; this fails before that ships.
	for _, desc := range []grpc.ServiceDesc{ipcv1.ProcessControlService_ServiceDesc, ipcv1.DatapathService_ServiceDesc, ipcv1.GatewayServicesService_ServiceDesc} {
		for _, m := range desc.Methods {
			method := "/" + desc.ServiceName + "/" + m.MethodName
			if _, ok := methodAdmissions[method]; !ok {
				t.Errorf("%s has no policy entry", method)
			}
		}
	}
}

func TestListen_ReplacesStaleSocketAndRefusesOtherFiles(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "gwipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	stale := filepath.Join(dir, "stale.sock")
	first := NewServer(&fakeNode{}, Policy{})
	if err := first.Listen(stale, 0o600, -1); err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	// Abandon the first listener without removing its socket file, the way
	// a crashed child does, and make sure the next instance takes over.
	first.listener.(interface{ SetUnlinkOnClose(bool) }).SetUnlinkOnClose(false)
	first.Stop()
	second := NewServer(&fakeNode{}, Policy{})
	if err := second.Listen(stale, 0o660, -1); err != nil {
		t.Fatalf("second Listen over stale socket: %v", err)
	}
	info, err := os.Stat(stale)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %v, want 0660", info.Mode().Perm())
	}
	second.Stop()

	regular := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var pathErr *ErrSocketPath
	if err := NewServer(&fakeNode{}, Policy{}).Listen(regular, 0o600, -1); !errors.As(err, &pathErr) {
		t.Fatalf("Listen over a regular file = %v, want *ErrSocketPath", err)
	}
	if _, err := os.Stat(regular); err != nil {
		t.Fatalf("regular file was removed: %v", err)
	}
}

// socketDir is a short directory for a Unix socket (sun_path is 108 bytes),
// setgid like the supervisor's control-socket directory, and its group.
func socketDir(t *testing.T) (string, int) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gwipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, os.ModeSetgid|0o770); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("%s mode %v: the kernel dropped the setgid bit", dir, info.Mode())
	}
	return dir, int(info.Sys().(*syscall.Stat_t).Gid)
}

// deniedChown stands for the datapath child: uid 0, but holding no CAP_CHOWN
// and not a member of the socket group, so every chown is EPERM.
type deniedChown struct{ calls int }

func (d *deniedChown) chown(string, int, int) error {
	d.calls++
	return syscall.EPERM
}

func TestListen_TakesTheGroupFromTheSetgidDirectoryWithoutAChown(t *testing.T) {
	// The supervisor makes the control-socket directory setgid and owned by
	// the service group, so the socket has the group the moment it is bound.
	// A child that could not chown still listens, and the mode is still set.
	dir, group := socketDir(t)
	path := filepath.Join(dir, "datapath.sock")
	srv := NewServer(&fakeNode{}, Policy{})
	denied := &deniedChown{}
	srv.chown = denied.chown
	if err := srv.Listen(path, 0o660, group); err != nil {
		t.Fatalf("Listen in a setgid directory: %v", err)
	}
	t.Cleanup(srv.Stop)
	if denied.calls != 0 {
		t.Fatalf("chown called %d times for a socket that already had the group", denied.calls)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %v, want 0660", info.Mode().Perm())
	}
	if gid := info.Sys().(*syscall.Stat_t).Gid; int(gid) != group {
		t.Fatalf("socket group = %d, want the directory's %d", gid, group)
	}
}

func TestListen_RefusesASocketItCannotGiveTheGroup(t *testing.T) {
	// A group the socket did not inherit needs a chown; without the privilege
	// that is a typed error naming both groups, not a readiness timeout.
	dir, group := socketDir(t)
	path := filepath.Join(dir, "datapath.sock")
	srv := NewServer(&fakeNode{}, Policy{})
	denied := &deniedChown{}
	srv.chown = denied.chown
	want := group + 1

	err := srv.Listen(path, 0o660, want)
	var groupErr *ErrSocketGroup
	if !errors.As(err, &groupErr) {
		t.Fatalf("Listen = %v, want *ErrSocketGroup", err)
	}
	if groupErr.Want != want || groupErr.Got != group || !errors.Is(err, syscall.EPERM) {
		t.Fatalf("ErrSocketGroup = %+v", groupErr)
	}
	if denied.calls != 1 {
		t.Fatalf("chown called %d times, want 1", denied.calls)
	}
	if addr := srv.Addr(); addr != "" {
		t.Fatalf("a refused Listen kept its listener at %q", addr)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("a refused Listen left its socket behind: %v", err)
	}
}

func TestServe_RequiresListen(t *testing.T) {
	var notListening *ErrServerNotListening
	if err := NewServer(&fakeNode{}, Policy{}).Serve(); !errors.As(err, &notListening) {
		t.Fatalf("Serve without Listen = %v", err)
	}
	if addr := NewServer(&fakeNode{}, Policy{}).Addr(); addr != "" {
		t.Fatalf("Addr before Listen = %q", addr)
	}
}

func TestDial_RejectsAnEmptyPath(t *testing.T) {
	var pathErr *ErrSocketPath
	if _, err := Dial(""); !errors.As(err, &pathErr) || !errors.Is(err, ErrEmptySocketPath) {
		t.Fatalf("Dial(\"\") = %v, want *ErrSocketPath wrapping ErrEmptySocketPath", err)
	}
}

// The supervisor dials a child right after exec and polls Status until the
// child listens. With gRPC's default backoff the channel stayed shut for at
// least 800ms after the first refused connect (1s base, 20% jitter), so a
// child that listened a moment late was not reached until long after it
// served — the relaunch timeouts of #955. The poll bound sits below that.
func TestDial_ReachesASocketThatListensAfterARefusedConnect(t *testing.T) {
	const reachBound = 600 * time.Millisecond

	dir, err := os.MkdirTemp("/tmp", "gwipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "p.sock")

	client, err := Dial(path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	if _, err := client.Status(testContext(t)); err == nil {
		t.Fatal("Status succeeded with nothing listening")
	}

	srv := NewServer(&fakeNode{state: gateway.GatewayStateRunning}, selfPolicy())
	if err := srv.Listen(path, 0o600, -1); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()
	t.Cleanup(func() {
		srv.Stop()
		if err := <-served; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	})

	listened := time.Now()
	deadline := time.NewTimer(reachBound)
	defer deadline.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for {
		_, err := client.Status(testContext(t))
		if err == nil {
			t.Logf("reached %v after the socket listened", time.Since(listened).Round(time.Millisecond))
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("Status still failing %v after the socket listened: %v", reachBound, err)
		case <-poll.C:
		}
	}
}

func TestErrors_Messages(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&ErrPeerDenied{Method: "svc", UID: 7, PID: 9}, "gatewayd ipc: uid 7 (pid 9) is not admitted to svc"},
		{&ErrUnknownService{Method: "m"}, "gatewayd ipc: no peer policy for method \"m\""},
		{&ErrSocketPath{Path: "/p", Op: "listen", Cause: errors.New("boom")}, "gatewayd ipc: listen \"/p\": boom"},
		{&ErrDocument{Document: "snapshot", Cause: errors.New("bad")}, "gatewayd ipc: snapshot document: bad"},
		{&ErrRemoteApply{Message: "x"}, "gatewayd ipc: datapath apply failed: x"},
		{&ErrServerNotListening{}, "gatewayd ipc: server has no listener; call Listen first"},
		{&ErrRemoteService{Message: "m"}, "m"},
		{&ErrRemoteService{Sentinel: errors.New("sentinel")}, "sentinel"},
		{&ErrServiceUnreachable{Socket: "/s", Service: "nat64", Cause: errors.New("eof")}, "gatewayd ipc: nat64 unreachable on \"/s\": eof"},
		{&ErrConntrackZone{Zone: -1}, "gatewayd ipc: conntrack zone -1 is out of range"},
		{&ErrVIPKey{Address: "x", Cause: errors.New("bad")}, "gatewayd ipc: VIP address \"x\": bad"},
		{
			&ErrSocketGroup{Path: "/p", Want: 65534, Got: 0, Cause: errors.New("denied")},
			"gatewayd ipc: socket \"/p\" has group 0, not 65534, and cannot be given it " +
				"(the control-socket directory must be setgid and owned by that group): denied",
		},
	}
	for _, c := range cases {
		if got := c.err.Error(); got != c.want {
			t.Errorf("%T = %q, want %q", c.err, got, c.want)
		}
	}
	cause := errors.New("cause")
	if !errors.Is(&ErrSocketPath{Cause: cause}, cause) || !errors.Is(&ErrDocument{Cause: cause}, cause) ||
		!errors.Is(&ErrSocketGroup{Cause: cause}, cause) || !errors.Is(&ErrVIPKey{Cause: cause}, cause) ||
		!errors.Is(&ErrServiceUnreachable{Cause: cause}, cause) || !errors.Is(&ErrRemoteService{Sentinel: cause}, cause) {
		t.Fatal("Unwrap does not reach the cause")
	}
}
