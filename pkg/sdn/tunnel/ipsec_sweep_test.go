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

package tunnel

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vnl "github.com/vishvananda/netlink"
)

// recordingXfrm records the order of XFRM deletions over the mock's state.
type recordingXfrm struct {
	*mockNetlinkOps
	deleted []string
}

func (r *recordingXfrm) XfrmStateDel(state *vnl.XfrmState) error {
	r.deleted = append(r.deleted, "sa:"+state.Dst.String()+":"+spiLabel(state.Spi))
	return r.mockNetlinkOps.XfrmStateDel(state)
}

func (r *recordingXfrm) XfrmPolicyDel(policy *vnl.XfrmPolicy) error {
	r.deleted = append(r.deleted, "policy:"+policy.Dst.String())
	return r.mockNetlinkOps.XfrmPolicyDel(policy)
}

func (r *recordingXfrm) LinkDel(link vnl.Link) error {
	r.deleted = append(r.deleted, "link:"+link.Attrs().Name)
	return r.mockNetlinkOps.LinkDel(link)
}

func spiLabel(spi int) string {
	return strconv.FormatInt(int64(spi), 16)
}

// foreignSA is an SA an IKE daemon would install between the same hosts:
// the same shape, but a request id that is not its SPI.
func foreignSA(cfg TunnelConfig) *vnl.XfrmState {
	return espState(net.ParseIP(cfg.Local), net.ParseIP(cfg.Remote), 0xc0ffee01, 7, 0, espKey(0xCC))
}

// foreignPolicy is an IKE daemon's policy for other hosts, under the
// foreign SA's request id.
func foreignPolicy() *vnl.XfrmPolicy {
	return espPolicy(net.ParseIP("203.0.113.1"), net.ParseIP("203.0.113.2"), vnl.Proto(17), vnl.XFRM_DIR_OUT, 7)
}

// blockPolicy is a templateless block policy like the overlay installs.
func blockPolicy() *vnl.XfrmPolicy {
	return &vnl.XfrmPolicy{
		Src: hostNet(net.ParseIP("203.0.113.9")), Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Dir: vnl.XFRM_DIR_OUT, Action: vnl.XFRM_POLICY_BLOCK,
	}
}

// rekeyedSPIs is cfg after a configuration change that moved its SPIs.
func rekeyedSPIs(cfg TunnelConfig) TunnelConfig {
	ipsec := *cfg.IPsec
	ipsec.SPIOut, ipsec.SPIIn = 0x2001, 0x2002
	cfg.IPsec = &ipsec
	return cfg
}

func TestManager_SweepIPsec_RemovesSAsUnderSPIsTheConfigNoLongerNames(t *testing.T) {
	old := ipsecConfig()
	mock, inventory := leftIPsec(t, old)
	mock.xfrmStates = append(mock.xfrmStates, foreignSA(old))
	mock.xfrmPolicies = append(mock.xfrmPolicies, foreignPolicy(), blockPolicy())
	cfg := rekeyedSPIs(old)
	relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), inventory)
	require.NoError(t, relaunched.EnsureTunnel(context.Background(), cfg))
	out, in := stateBySPI(mock, cfg.IPsec.SPIOut), stateBySPI(mock, cfg.IPsec.SPIIn)
	policies := mock.xfrmPolicyUpdates

	require.NoError(t, relaunched.SweepIPsec())

	assert.Nil(t, stateBySPI(mock, old.IPsec.SPIOut), "the old outbound SA is removed")
	assert.Nil(t, stateBySPI(mock, old.IPsec.SPIIn), "the old inbound SA is removed")
	assert.Same(t, out, stateBySPI(mock, cfg.IPsec.SPIOut), "the named outbound SA is kept")
	assert.Same(t, in, stateBySPI(mock, cfg.IPsec.SPIIn), "the named inbound SA is kept")
	assert.NotNil(t, stateBySPI(mock, 0xc0ffee01), "an SA another installer owns is never touched")
	assert.Len(t, mock.xfrmPolicies, 4, "the tunnel's two policies and the two foreign ones remain")
	assert.Equal(t, policies, mock.xfrmPolicyUpdates, "the sweep rewrites no policy")
}

func TestManager_SweepIPsec_RemovesATunnelDroppedWhileNoManagerRan(t *testing.T) {
	cfg := ipsecConfig()
	mock, inventory := leftIPsec(t, cfg)
	rec := &recordingXfrm{mockNetlinkOps: mock}
	rec.xfrmPolicies = append(rec.xfrmPolicies, foreignPolicy(), blockPolicy())
	other := &vnl.Gretun{LinkAttrs: vnl.LinkAttrs{Name: "gre-other"},
		Local: net.ParseIP(cfg.Local), Remote: net.ParseIP("198.51.100.77")}
	rec.links[other.Name] = other
	// Another installer's keyed GRE link between the same hosts: its
	// endpoints and protocol match the stale policies, but the inventory
	// does not name it, so nothing proves it the platform's.
	foreign := &vnl.Gretun{LinkAttrs: vnl.LinkAttrs{Name: "gre-foreign"},
		Local: net.ParseIP(cfg.Local), Remote: net.ParseIP(cfg.Remote), IKey: 7, OKey: 7}
	rec.links[foreign.Name] = foreign
	relaunched := newManagerWithOps(testLogger(), rec, WithKeyProvider(keysFor(cfg)), inventory)

	require.NoError(t, relaunched.SweepIPsec())

	assert.Contains(t, rec.links, foreign.Name, "a carrier the inventory does not name is never touched")
	assert.Empty(t, rec.xfrmStates, "the dropped tunnel's SAs are removed")
	assert.Equal(t, []*vnl.XfrmPolicy{foreignPolicy(), blockPolicy()}, rec.xfrmPolicies,
		"only the dropped tunnel's policies are removed")
	assert.NotContains(t, rec.links, cfg.Name, "the dropped tunnel's carrier is removed")
	assert.Contains(t, rec.links, other.Name, "a carrier on other endpoints is never touched")
	require.Len(t, rec.deleted, 5)
	assert.Equal(t, "link:"+cfg.Name, rec.deleted[0],
		"the carrier goes before its protection, so it never sends in the clear")
	assert.ElementsMatch(t, []string{"policy:198.51.100.100/32", "policy:198.51.100.36/32"}, rec.deleted[1:3],
		"policies go next, so none selects traffic into a removed SA")
	assert.Equal(t, []string{"sa:198.51.100.36:" + spiLabel(0x1002), "sa:198.51.100.100:" + spiLabel(0x1001)}, rec.deleted[3:],
		"the inbound SA goes before the outbound anchor")
	for _, key := range rec.listedKeys {
		assert.Equal(t, make([]byte, len(key)), key, "every key the dump carried is zeroized")
	}
}

// withoutOutboundSA is the kernel a kill leaves between reconcileState's
// delete of a differing outbound SA and the add of its replacement: the
// tunnel's inbound SA, policies and carrier are installed and recorded, its
// outbound SA, the pair's anchor, is gone.
func withoutOutboundSA(t *testing.T, cfg TunnelConfig) (*recordingXfrm, *ipsecInventory) {
	t.Helper()
	mock, inv := leftIPsecRecorded(t, cfg)
	out := stateBySPI(mock, cfg.IPsec.SPIOut)
	require.NotNil(t, out)
	require.NoError(t, mock.XfrmStateDel(out))
	require.NotNil(t, stateBySPI(mock, cfg.IPsec.SPIIn))
	require.NotEmpty(t, mock.xfrmPolicies)
	require.Contains(t, mock.links, cfg.Name)
	return &recordingXfrm{mockNetlinkOps: mock}, inv
}

func TestManager_SweepIPsec_RemovesARecordedPairWithoutItsOutboundSA(t *testing.T) {
	cfg := ipsecConfig()
	rec, inv := withoutOutboundSA(t, cfg)
	relaunched := newManagerWithOps(testLogger(), rec, WithIPsecInventory(inv.path))

	require.NoError(t, relaunched.SweepIPsec())

	assert.Empty(t, rec.xfrmStates, "the inbound SA goes although its anchor is gone")
	assert.Empty(t, rec.xfrmPolicies, "the policies go although their anchor is gone")
	assert.NotContains(t, rec.links, cfg.Name, "the carrier goes although its anchor is gone")
	assert.NotContains(t, rec.deleted, "sa:"+cfg.Remote+":"+spiLabel(int(cfg.IPsec.SPIOut)),
		"the recorded anchor the kernel no longer holds is never deleted")
	recorded, err := inv.load()
	require.NoError(t, err)
	assert.Empty(t, recorded, "the record goes only once every recorded object is gone")
}

func TestManager_SweepIPsec_KeepsTheRecordOfAPairWithoutItsOutboundSAWhenASweepFails(t *testing.T) {
	cfg := ipsecConfig()
	rec, inv := withoutOutboundSA(t, cfg)
	boom := errors.New("EPERM")
	rec.xfrmStateDelFn = func(*vnl.XfrmState) error { return boom }
	relaunched := newManagerWithOps(testLogger(), rec, WithIPsecInventory(inv.path))

	err := relaunched.SweepIPsec()

	require.ErrorIs(t, err, boom)
	recorded, loadErr := inv.load()
	require.NoError(t, loadErr)
	assert.Len(t, recorded, 1, "a partly swept pair keeps its record, so a later sweep still finds it")

	rec.xfrmStateDelFn = nil
	require.NoError(t, relaunched.SweepIPsec())
	assert.Empty(t, rec.xfrmStates, "the next sweep finishes from the kept record")
	recorded, loadErr = inv.load()
	require.NoError(t, loadErr)
	assert.Empty(t, recorded)
}

// A killed predecessor's keyed GRE tunnel is replaced by one with another
// name, key and SPIs on the same endpoints. The replacement updates the old
// policies in place, since their selectors are unchanged, so no policy is
// stale; the old pair's SAs and inventory entry still go, so its carrier
// must go with them rather than stay up untracked and send in the clear once
// the replacement's policies are removed.
func TestManager_SweepIPsec_RemovesTheCarrierOfAReplacedTunnel(t *testing.T) {
	old := ipsecConfig()
	old.Key = 7
	mock, inventory := leftIPsec(t, old)
	rec := &recordingXfrm{mockNetlinkOps: mock}
	replacement := rekeyedSPIs(old)
	replacement.Name, replacement.Key = "gre-new", 9
	relaunched := newManagerWithOps(testLogger(), rec, WithKeyProvider(keysFor(replacement)), inventory)
	require.NoError(t, relaunched.EnsureTunnel(context.Background(), replacement))
	require.Len(t, rec.xfrmPolicies, 2, "the replacement updates the old policies in place")

	require.NoError(t, relaunched.SweepIPsec())

	assert.NotContains(t, rec.links, old.Name, "the replaced tunnel's carrier is removed")
	assert.Contains(t, rec.links, replacement.Name, "the replacement's carrier is kept")
	assert.Nil(t, stateBySPI(mock, old.IPsec.SPIOut), "the old outbound SA is removed")
	assert.Nil(t, stateBySPI(mock, old.IPsec.SPIIn), "the old inbound SA is removed")
	assert.NotNil(t, stateBySPI(mock, replacement.IPsec.SPIOut), "the named outbound SA is kept")
	assert.NotNil(t, stateBySPI(mock, replacement.IPsec.SPIIn), "the named inbound SA is kept")
	assert.Len(t, rec.xfrmPolicies, 2, "the replacement's policies are kept")
	require.NotEmpty(t, rec.deleted)
	assert.Equal(t, "link:"+old.Name, rec.deleted[0], "the carrier goes before its SAs")

	again := newManagerWithOps(testLogger(), rec, WithKeyProvider(keysFor(replacement)), inventory)
	require.NoError(t, again.EnsureTunnel(context.Background(), replacement))
	require.NoError(t, again.SweepIPsec())
	assert.Contains(t, rec.links, replacement.Name, "a later sweep keeps the replacement's carrier")
}

// leftIPsecRecorded is leftIPsec with the inventory's path, for a test that
// reads the record the sweep leaves.
func leftIPsecRecorded(t *testing.T, cfg TunnelConfig) (*mockNetlinkOps, *ipsecInventory) {
	t.Helper()
	mock := newMockNetlinkOps()
	inv := &ipsecInventory{path: filepath.Join(t.TempDir(), "ipsec-installed.json")}
	killed := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), WithIPsecInventory(inv.path))
	require.NoError(t, killed.EnsureTunnel(context.Background(), cfg))
	return mock, inv
}

func TestManager_SweepIPsec_RetiresTheCarrierOfAReplacementThatReusesItsPair(t *testing.T) {
	old := ipsecConfig()
	mock, inv := leftIPsecRecorded(t, old)
	rec := &recordingXfrm{mockNetlinkOps: mock}
	// Replaced while no manager ran by an IPIP tunnel of another name on the
	// same endpoints and SPIs: the pair stays named, the GRE carrier does not.
	replacement := old
	replacement.Name, replacement.Type = "ipip-new", TunnelTypeIPIP
	relaunched := newManagerWithOps(testLogger(), rec, WithKeyProvider(keysFor(replacement)), WithIPsecInventory(inv.path))
	require.NoError(t, relaunched.EnsureTunnel(context.Background(), replacement))
	out, in := stateBySPI(mock, old.IPsec.SPIOut), stateBySPI(mock, old.IPsec.SPIIn)
	require.Len(t, rec.xfrmPolicies, 4, "the old GRE policies stay beside the replacement's IPIP ones")

	require.NoError(t, relaunched.SweepIPsec())

	assert.NotContains(t, rec.links, old.Name, "the replaced GRE carrier is removed")
	assert.Contains(t, rec.links, replacement.Name, "the replacement's carrier is kept")
	assert.Same(t, out, stateBySPI(mock, old.IPsec.SPIOut), "the shared outbound SA is kept")
	assert.Same(t, in, stateBySPI(mock, old.IPsec.SPIIn), "the shared inbound SA is kept")
	require.Len(t, rec.xfrmPolicies, 2, "the GRE policies are removed")
	for _, p := range rec.xfrmPolicies {
		assert.Equal(t, carrierProto(TunnelTypeIPIP), p.Proto, "only the replacement's policies remain")
	}
	require.NotEmpty(t, rec.deleted)
	assert.Equal(t, "link:"+old.Name, rec.deleted[0], "the GRE carrier goes before its policies")
	for _, d := range rec.deleted {
		assert.NotContains(t, d, "sa:", "no SA of the shared pair is removed")
	}
	recorded, err := inv.load()
	require.NoError(t, err)
	require.Contains(t, recorded, recordOf(out))
	assert.Equal(t, []string{replacement.Name}, recorded[recordOf(out)].Carriers,
		"the retired carrier leaves the record, the replacement's stays")
}

func TestManager_SweepIPsec_LeavesAForeignSAUnderTheAnchorsReqid(t *testing.T) {
	old := ipsecConfig()
	mock, inv := leftIPsecRecorded(t, old)
	local, remote := net.ParseIP(old.Local), net.ParseIP(old.Remote)
	reqid := ipsecReqid(old.IPsec)
	// An IKE daemon's SAs under the platform anchor's request id and between
	// the same hosts, under SPIs of its own.
	foreignOut := espState(local, remote, 0xc0ffee02, reqid, 0, espKey(0xCD))
	foreignIn := espState(remote, local, 0xc0ffee03, reqid, 0, espKey(0xCE))
	mock.xfrmStates = append(mock.xfrmStates, foreignOut, foreignIn)
	// The inbound SPI changed while no manager ran, so the old inbound SA is
	// obsolete but still the platform's.
	cfg := old
	ipsec := *old.IPsec
	ipsec.SPIIn = 0x1003
	cfg.IPsec = &ipsec
	relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), WithIPsecInventory(inv.path))
	require.NoError(t, relaunched.EnsureTunnel(context.Background(), cfg))
	out := stateBySPI(mock, cfg.IPsec.SPIOut)

	require.NoError(t, relaunched.SweepIPsec())

	assert.Nil(t, stateBySPI(mock, old.IPsec.SPIIn), "the recorded obsolete inbound SA is removed")
	assert.Same(t, out, stateBySPI(mock, cfg.IPsec.SPIOut), "the named anchor is kept")
	assert.NotNil(t, stateBySPI(mock, cfg.IPsec.SPIIn), "the named inbound SA is kept")
	assert.Same(t, foreignOut, stateBySPI(mock, 0xc0ffee02), "an unrecorded SA under the anchor's reqid is never touched")
	assert.Same(t, foreignIn, stateBySPI(mock, 0xc0ffee03), "an unrecorded SA under the anchor's reqid is never touched")
	recorded, err := inv.load()
	require.NoError(t, err)
	require.Contains(t, recorded, recordOf(out))
	_, in := ipsecStates(cfg, nil, nil)
	assert.ElementsMatch(t, []ipsecSARecord{saRecordOf(out), saRecordOf(in)}, recorded[recordOf(out)].SAs,
		"the swept SA leaves the record")
}

func TestManager_SweepIPsec_LeavesAForeignPolicyUnderTheAnchorsReqid(t *testing.T) {
	cfg := ipsecConfig()
	mock, inv := leftIPsecRecorded(t, cfg)
	local, remote := net.ParseIP(cfg.Local), net.ParseIP(cfg.Remote)
	reqid := ipsecReqid(cfg.IPsec)
	// Another installer protects an IPIP carrier between the platform GRE
	// pair's hosts under the pair's request id: its template names the
	// recorded anchor's endpoints and request id, but the inventory does
	// not record its selector.
	foreignOut := espPolicy(local, remote, carrierProto(TunnelTypeIPIP), vnl.XFRM_DIR_OUT, reqid)
	foreignIn := espPolicy(remote, local, carrierProto(TunnelTypeIPIP), vnl.XFRM_DIR_IN, reqid)
	mock.xfrmPolicies = append(mock.xfrmPolicies, foreignOut, foreignIn)
	relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), WithIPsecInventory(inv.path))

	require.NoError(t, relaunched.SweepIPsec())

	assert.Equal(t, []*vnl.XfrmPolicy{foreignOut, foreignIn}, mock.xfrmPolicies,
		"the dropped tunnel's recorded policies are removed and the foreign ones are never touched")
	assert.Empty(t, mock.xfrmStates, "the dropped tunnel's SAs are removed")
	recorded, err := inv.load()
	require.NoError(t, err)
	assert.Empty(t, recorded, "the retired pair's record goes with its anchor")
}

// Another installer's policy that carries the dropped pair's recorded
// selector and template plus one field espPolicy never sets is another
// policy, so the sweep leaves it. A field in the kernel's policy key
// (interface, ports, mark, interface id) lets it coexist with the
// platform's wildcard policy; any other field means it replaced the
// platform's policy under the same key.
func TestManager_SweepIPsec_LeavesAForeignPolicyWithAFieldThePlatformNeverSets(t *testing.T) {
	tests := []struct {
		name  string
		keyed bool
		scope func(p *vnl.XfrmPolicy)
	}{
		{"interface", true, func(p *vnl.XfrmPolicy) { p.Ifindex = 7 }},
		{"source port", true, func(p *vnl.XfrmPolicy) { p.SrcPort = 4500 }},
		{"destination port", true, func(p *vnl.XfrmPolicy) { p.DstPort = 4500 }},
		{"mark", true, func(p *vnl.XfrmPolicy) { p.Mark = &vnl.XfrmMark{Value: 1, Mask: 0xffffffff} }},
		{"interface id", true, func(p *vnl.XfrmPolicy) { p.Ifid = 3 }},
		{"priority", false, func(p *vnl.XfrmPolicy) { p.Priority = 100 }},
		{"template spi", false, func(p *vnl.XfrmPolicy) { p.Tmpls[0].Spi = 0x1001 }},
		{"optional template", false, func(p *vnl.XfrmPolicy) { p.Tmpls[0].Optional = 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ipsecConfig()
			mock, inv := leftIPsecRecorded(t, cfg)
			out, in := ipsecPolicies(cfg)
			tt.scope(out)
			tt.scope(in)
			if tt.keyed {
				mock.xfrmPolicies = append(mock.xfrmPolicies, out, in)
			} else {
				mock.xfrmPolicies = []*vnl.XfrmPolicy{out, in}
			}
			relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), WithIPsecInventory(inv.path))

			require.NoError(t, relaunched.SweepIPsec())

			assert.Equal(t, []*vnl.XfrmPolicy{out, in}, mock.xfrmPolicies,
				"only the dropped tunnel's recorded policies are removed; the foreign ones are never touched")
			assert.Empty(t, mock.xfrmStates, "the dropped tunnel's SAs are removed")
		})
	}
}

func TestManager_SweepIPsec_ForgetsTheRecordedPolicyOfAReplacedCarrierProtocol(t *testing.T) {
	old := ipsecConfig()
	mock, inv := leftIPsecRecorded(t, old)
	oldOut, oldIn := ipsecPolicies(old)
	// The same pair now protects an IPIP carrier: the GRE policies the
	// predecessor recorded are stale while the pair stays named.
	cfg := old
	cfg.Name, cfg.Type = "ipip-pri", TunnelTypeIPIP
	relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), WithIPsecInventory(inv.path))
	require.NoError(t, relaunched.EnsureTunnel(context.Background(), cfg))

	require.NoError(t, relaunched.SweepIPsec())

	newOut, newIn := ipsecPolicies(cfg)
	assert.ElementsMatch(t, []*vnl.XfrmPolicy{newOut, newIn}, mock.xfrmPolicies,
		"the stale GRE policies are removed and the named IPIP ones kept")
	recorded, err := inv.load()
	require.NoError(t, err)
	out, _ := ipsecStates(cfg, nil, nil)
	require.Contains(t, recorded, recordOf(out))
	entry := recorded[recordOf(out)]
	assert.ElementsMatch(t, []ipsecPolicyRecord{policyRecordOf(newOut), policyRecordOf(newIn)}, entry.Policies,
		"the swept policies leave the record")
	assert.NotContains(t, entry.Policies, policyRecordOf(oldOut))
	assert.NotContains(t, entry.Policies, policyRecordOf(oldIn))
}

// A dropped carrier that cannot be removed keeps its protection: the sweep
// fails before it deletes a policy, so the carrier fails closed rather than
// sending in the clear.
func TestManager_SweepIPsec_KeepsProtectionWhileTheStaleCarrierStays(t *testing.T) {
	cfg := ipsecConfig()
	for name, inject := range map[string]func(*mockNetlinkOps){
		"list links": func(m *mockNetlinkOps) {
			m.linkListFn = func() ([]vnl.Link, error) { return nil, errors.New("netlink busy") }
		},
		"remove carrier": func(m *mockNetlinkOps) { m.linkDelFn = func(vnl.Link) error { return errors.New("netlink busy") } },
	} {
		t.Run(name, func(t *testing.T) {
			mock, inventory := leftIPsec(t, cfg)
			inject(mock)
			relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), inventory)

			err := relaunched.SweepIPsec()

			var sweepErr *ErrIPsecSweepFailed
			require.ErrorAs(t, err, &sweepErr)
			assert.Equal(t, name, sweepErr.Op)
			assert.Len(t, mock.xfrmPolicies, 2, "the carrier's policies stay")
			assert.Len(t, mock.xfrmStates, 2, "the carrier's SAs stay")
		})
	}
}

// An endpoint change that keeps SPIOut leaves two anchors under one request
// id: the old pair's and the new one's. Each is its own pair, whichever the
// dump lists last, so the old pair's SA and policies go and the new pair's
// stay.
func TestManager_SweepIPsec_RemovesTheOldPairWhenTheRemoteMovesUnderTheSameSPIs(t *testing.T) {
	for name, reverse := range map[string]bool{"installed order": false, "reversed order": true} {
		t.Run(name, func(t *testing.T) {
			old := ipsecConfig()
			mock, inventory := leftIPsec(t, old)
			cfg := old
			cfg.Remote = "198.51.100.200"
			relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), inventory)
			require.NoError(t, relaunched.EnsureTunnel(context.Background(), cfg))
			require.Len(t, mock.xfrmStates, 3, "the old outbound SA outlives the move")
			require.Len(t, mock.xfrmPolicies, 4, "the old pair's policies outlive the move")
			if reverse {
				slices.Reverse(mock.xfrmStates)
			}
			newOut, _ := ipsecStates(cfg, nil, nil)
			wantPolOut, wantPolIn := ipsecPolicies(cfg)

			require.NoError(t, relaunched.SweepIPsec())

			require.Len(t, mock.xfrmStates, 2, "only the new pair's SAs remain")
			for _, s := range mock.xfrmStates {
				assert.True(t, pairEndpoints(s.Src, s.Dst, newOut), "SA %s->%s is the new pair's", s.Src, s.Dst)
			}
			require.Len(t, mock.xfrmPolicies, 2, "only the new pair's policies remain")
			assert.ElementsMatch(t,
				[]policyKey{keyOfPolicy(wantPolOut), keyOfPolicy(wantPolIn)},
				[]policyKey{keyOfPolicy(mock.xfrmPolicies[0]), keyOfPolicy(mock.xfrmPolicies[1])})
		})
	}
}

// A local endpoint that moves under the same remote and SPIs keeps the
// outbound SA's identity (destination and SPI), so ensuring the new pair
// replaces the old pair's anchor. The old inbound SA and policies must go
// with it, or no sweep could ever prove them this manager's again.
func TestManager_EnsureTunnel_RetiresTheOldPairWhenTheLocalMovesUnderTheSameSPIs(t *testing.T) {
	old := ipsecConfig()
	mock, inventory := leftIPsec(t, old)
	cfg := old
	cfg.Local = "198.51.100.37"
	relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), inventory)

	require.NoError(t, relaunched.EnsureTunnel(context.Background(), cfg))

	newOut, newIn := ipsecStates(cfg, nil, nil)
	require.Len(t, mock.xfrmStates, 2, "only the new pair's SAs remain")
	assert.ElementsMatch(t,
		[]saKey{keyOfSA(newOut), keyOfSA(newIn)},
		[]saKey{keyOfSA(mock.xfrmStates[0]), keyOfSA(mock.xfrmStates[1])})
	for _, s := range mock.xfrmStates {
		assert.True(t, pairEndpoints(s.Src, s.Dst, newOut), "SA %s->%s is the new pair's", s.Src, s.Dst)
	}
	wantPolOut, wantPolIn := ipsecPolicies(cfg)
	require.Len(t, mock.xfrmPolicies, 2, "only the new pair's policies remain")
	assert.ElementsMatch(t,
		[]policyKey{keyOfPolicy(wantPolOut), keyOfPolicy(wantPolIn)},
		[]policyKey{keyOfPolicy(mock.xfrmPolicies[0]), keyOfPolicy(mock.xfrmPolicies[1])})

	require.NoError(t, relaunched.SweepIPsec())
	assert.Len(t, mock.xfrmStates, 2, "the sweep keeps the ensured pair")
	assert.Len(t, mock.xfrmPolicies, 2, "the sweep keeps the ensured pair's policies")
}

// A retirement cut short fails the ensure but keeps the old pair's anchor, so
// the next start still recognises the old pair and retires it then.
func TestManager_EnsureTunnel_KeepsTheOldAnchorWhenRetiringFails(t *testing.T) {
	old := ipsecConfig()
	mock, inventory := leftIPsec(t, old)
	cfg := old
	cfg.Local = "198.51.100.37"
	cause := errors.New("policy delete refused")
	mock.xfrmPolicyDelFn = func(*vnl.XfrmPolicy) error { return cause }
	relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), inventory)

	err := relaunched.EnsureTunnel(context.Background(), cfg)

	var createErr *ErrTunnelCreateFailed
	require.ErrorAs(t, err, &createErr)
	var sweepErr *ErrIPsecSweepFailed
	require.ErrorAs(t, err, &sweepErr)
	assert.Equal(t, "remove policy", sweepErr.Op)
	assert.ErrorIs(t, err, cause)
	oldOut, _ := ipsecStates(old, nil, nil)
	anchor, getErr := mock.XfrmStateGet(oldOut)
	require.NoError(t, getErr, "the old pair's anchor survives the failed ensure")
	assert.True(t, anchor.Src.Equal(oldOut.Src), "the anchor is still the old pair's")

	mock.xfrmPolicyDelFn = nil
	require.NoError(t, relaunched.EnsureTunnel(context.Background(), cfg))
	assert.Len(t, mock.xfrmStates, 2, "the next ensure retires the old pair")
	assert.Len(t, mock.xfrmPolicies, 2, "the next ensure retires the old pair's policies")
}

// An SA under the outbound identity that this manager did not install (an
// IKE daemon's, whose SPI is not its request id) anchors no pair, so nothing
// else is retired for it.
func TestManager_EnsureTunnel_RetiresNothingForAForeignSA(t *testing.T) {
	cfg := ipsecConfig()
	mock := newMockNetlinkOps()
	ike := espState(net.ParseIP("198.51.100.99"), net.ParseIP(cfg.Remote), cfg.IPsec.SPIOut, 7, 0, espKey(0xCC))
	require.NoError(t, mock.recordState(ike))
	listed := 0
	mock.xfrmStateListFn = func(int) ([]vnl.XfrmState, error) {
		listed++
		return nil, nil
	}
	manager := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)))

	require.NoError(t, manager.EnsureTunnel(context.Background(), cfg))

	assert.Zero(t, listed, "no ownership lookup for a foreign SA")
	assert.Len(t, mock.xfrmStates, 2, "the new pair replaces the foreign SA at its identity, as before")
}

func TestManager_SweepIPsec_LeavesWhatItCannotProveItInstalled(t *testing.T) {
	cfg := ipsecConfig()
	local, remote := net.ParseIP(cfg.Local), net.ParseIP(cfg.Remote)
	other := net.ParseIP("192.0.2.77")
	encapped := espState(local, remote, 0x4001, 0x4001, 0, espKey(0x11))
	encapped.Encap = &vnl.XfrmStateEncap{Type: vnl.XFRM_ENCAP_ESPINUDP, SrcPort: 4500, DstPort: 4500}
	cbc := espState(local, remote, 0x5001, 0x5001, 0, nil)
	cbc.Aead = nil
	cbc.Crypt = &vnl.XfrmStateAlgo{Name: "cbc(aes)", Key: espKey(0x22)}
	anchor := espState(local, remote, 0x6001, 0x6001, 0, espKey(0x44))
	mock := newMockNetlinkOps()
	mock.xfrmStates = []*vnl.XfrmState{
		espState(remote, local, 0x3002, 0x3001, 0, espKey(0x33)), // a pair whose anchor is gone
		encapped, // UDP-encapsulated: not this manager's shape
		cbc,      // no AEAD: not this manager's shape
		anchor,   // a recorded anchor ...
		espState(other, local, 0x6002, 0x6001, 0, espKey(0x55)), // ... and an SA off its endpoints
		// A pair of this manager's exact shape, SPI equal to request id,
		// that the inventory does not record: another installer's.
		espState(local, remote, 0x7001, 0x7001, 0, espKey(0x66)),
		espState(remote, local, 0x7002, 0x7001, 0, espKey(0x77)),
	}
	unowned := espPolicy(remote, local, carrierProto(TunnelTypeGRE), vnl.XFRM_DIR_IN, 0x3001)
	unrecorded := espPolicy(local, remote, carrierProto(TunnelTypeGRE), vnl.XFRM_DIR_OUT, 0x7001)
	mock.xfrmPolicies = []*vnl.XfrmPolicy{unowned, unrecorded}
	// The record of the shapes the manager never installs proves nothing.
	m := newManagerWithOps(testLogger(), mock, recordedInventory(t, anchor, encapped, cbc))

	require.NoError(t, m.SweepIPsec())

	for _, spi := range []uint32{0x3002, 0x4001, 0x5001, 0x6002, 0x7001, 0x7002} {
		assert.NotNil(t, stateBySPI(mock, spi), "SA %#x is not provably this manager's", spi)
	}
	assert.Nil(t, stateBySPI(mock, 0x6001), "the recorded anchor is this manager's and named by nothing")
	assert.Equal(t, []*vnl.XfrmPolicy{unowned, unrecorded}, mock.xfrmPolicies,
		"a policy under an unanchored or unrecorded reqid stays")
}

func TestOwnedPolicy(t *testing.T) {
	cfg := ipsecConfig()
	anchor, _ := ipsecStates(cfg, espKey(1), espKey(2))
	out, in := ipsecPolicies(cfg)
	pair := &ownedPair{anchor: anchor, policies: []ipsecPolicyRecord{policyRecordOf(out), policyRecordOf(in)}}
	owned := map[int][]*ownedPair{anchor.Reqid: {pair}}
	require.Same(t, pair, ownedPolicy(out, owned), "the recorded policy espPolicy built is owned by its pair")
	require.Same(t, pair, ownedPolicy(in, owned), "the recorded inbound policy is owned by its pair")
	unrecorded := map[int][]*ownedPair{anchor.Reqid: {{anchor: anchor}}}
	assert.Nil(t, ownedPolicy(out, unrecorded), "a policy the pair's record does not name is not owned")

	mutations := map[string]func(p *vnl.XfrmPolicy){
		"block action":      func(p *vnl.XfrmPolicy) { p.Action = vnl.XFRM_POLICY_BLOCK },
		"marked":            func(p *vnl.XfrmPolicy) { p.Mark = &vnl.XfrmMark{Value: 1} },
		"no template":       func(p *vnl.XfrmPolicy) { p.Tmpls = nil },
		"forward direction": func(p *vnl.XfrmPolicy) { p.Dir = vnl.XFRM_DIR_FWD },
		"udp selector":      func(p *vnl.XfrmPolicy) { p.Proto = vnl.Proto(17) },
		"tunnel mode":       func(p *vnl.XfrmPolicy) { p.Tmpls[0].Mode = vnl.XFRM_MODE_TUNNEL },
		"ah template":       func(p *vnl.XfrmPolicy) { p.Tmpls[0].Proto = vnl.XFRM_PROTO_AH },
		"unknown reqid":     func(p *vnl.XfrmPolicy) { p.Tmpls[0].Reqid = 99 },
		"no selector":       func(p *vnl.XfrmPolicy) { p.Src = nil },
		"wide selector":     func(p *vnl.XfrmPolicy) { p.Dst.Mask = net.CIDRMask(24, 32) },
		"other endpoints":   func(p *vnl.XfrmPolicy) { p.Tmpls[0].Dst = net.ParseIP("192.0.2.77") },
		"unrecorded ipip":   func(p *vnl.XfrmPolicy) { p.Proto = carrierProto(TunnelTypeIPIP) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p, _ := ipsecPolicies(cfg)
			mutate(p)
			assert.Nil(t, ownedPolicy(p, owned))
		})
	}
}

func TestOwnedSAShape(t *testing.T) {
	cfg := ipsecConfig()
	built, _ := ipsecStates(cfg, espKey(1), espKey(2))
	require.True(t, ownedSAShape(built), "the SA espState built has the owned shape")

	mutations := map[string]func(s *vnl.XfrmState){
		"ah":          func(s *vnl.XfrmState) { s.Proto = vnl.XFRM_PROTO_AH },
		"tunnel mode": func(s *vnl.XfrmState) { s.Mode = vnl.XFRM_MODE_TUNNEL },
		"marked":      func(s *vnl.XfrmState) { s.Mark = &vnl.XfrmMark{Value: 1} },
		"udp encap":   func(s *vnl.XfrmState) { s.Encap = &vnl.XfrmStateEncap{Type: vnl.XFRM_ENCAP_ESPINUDP} },
		"no aead":     func(s *vnl.XfrmState) { s.Aead = nil },
		"other aead":  func(s *vnl.XfrmState) { s.Aead.Name = "rfc4309(ccm(aes))" },
		"short icv":   func(s *vnl.XfrmState) { s.Aead.ICVLen = 64 },
	}
	for name, mutate := range foreignSAFields() {
		mutations[name] = mutate
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s, _ := ipsecStates(cfg, espKey(1), espKey(2))
			mutate(s)
			assert.False(t, ownedSAShape(s))
		})
	}
}

// foreignSAFields sets, one each, the SA fields espState never sets.
func foreignSAFields() map[string]func(s *vnl.XfrmState) {
	pcpu := uint32(1)
	return map[string]func(s *vnl.XfrmState){
		"output mark":       func(s *vnl.XfrmState) { s.OutputMark = &vnl.XfrmMark{Value: 1} },
		"interface id":      func(s *vnl.XfrmState) { s.Ifid = 3 },
		"sa direction":      func(s *vnl.XfrmState) { s.SADir = vnl.XFRM_SA_DIR_IN },
		"per-cpu":           func(s *vnl.XfrmState) { s.Pcpunum = &pcpu },
		"dont encap dscp":   func(s *vnl.XfrmState) { s.DontEncapDSCP = true },
		"oseq may wrap":     func(s *vnl.XfrmState) { s.OSeqMayWrap = true },
		"selector iface":    func(s *vnl.XfrmState) { s.Selector = &vnl.XfrmPolicy{Ifindex: 7} },
		"selector src port": func(s *vnl.XfrmState) { s.Selector = &vnl.XfrmPolicy{SrcPort: 4500} },
		"selector dst port": func(s *vnl.XfrmState) { s.Selector = &vnl.XfrmPolicy{DstPort: 4500} },
		"selector proto":    func(s *vnl.XfrmState) { s.Selector = &vnl.XfrmPolicy{Proto: vnl.Proto(47)} },
		"selector src v4":   func(s *vnl.XfrmState) { s.Selector = &vnl.XfrmPolicy{Src: prefix("10.1.0.0", 16, 32)} },
		"selector dst v4":   func(s *vnl.XfrmState) { s.Selector = &vnl.XfrmPolicy{Dst: prefix("10.2.0.5", 32, 32)} },
		"selector src v6":   func(s *vnl.XfrmState) { s.Selector = &vnl.XfrmPolicy{Src: prefix("fd00:1::", 64, 128)} },
		"selector dst v6":   func(s *vnl.XfrmState) { s.Selector = &vnl.XfrmPolicy{Dst: prefix("fd00:2::1", 128, 128)} },
		"selector src addr, zero prefix": func(s *vnl.XfrmState) {
			s.Selector = &vnl.XfrmPolicy{Src: prefix("10.1.0.0", 0, 32)}
		},
		"selector dst addr, zero prefix": func(s *vnl.XfrmState) {
			s.Selector = &vnl.XfrmPolicy{Dst: prefix("fd00:2::1", 0, 128)}
		},
	}
}

// prefix builds a selector prefix the way netlink reports one: an address
// with a CIDR mask of the given length.
func prefix(ip string, ones, bits int) *net.IPNet {
	return &net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(ones, bits)}
}

// An SA whose selector addresses are each a form netlink reports for an
// unset selector address keeps the owned shape.
func TestOwnedSAShape_UnsetSelectorAddresses(t *testing.T) {
	unset := map[string]*net.IPNet{
		"nil":          nil,
		"v4":           prefix("0.0.0.0", 0, 32),
		"v4 four-byte": {IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
		"v6":           prefix("::", 0, 128),
	}
	cfg := ipsecConfig()
	for srcName, src := range unset {
		for dstName, dst := range unset {
			t.Run(srcName+" to "+dstName, func(t *testing.T) {
				s, _ := ipsecStates(cfg, espKey(1), espKey(2))
				s.Selector = &vnl.XfrmPolicy{Src: src, Dst: dst}
				assert.True(t, ownedSAShape(s))
			})
		}
	}
}

// Another installer's SA that replaced the dropped pair's recorded inbound
// SA under the same destination and SPI, carrying a field espState never
// sets, is not the platform's: the sweep removes the rest of the pair and
// leaves it.
func TestManager_SweepIPsec_LeavesAForeignSAThatReplacedARecordedOne(t *testing.T) {
	// One foreign field proves the sweep asks ownedSAShape; TestOwnedSAShape
	// runs every field in foreignSAFields through it.
	cfg := ipsecConfig()
	mock, inv := leftIPsecRecorded(t, cfg)
	recorded := stateBySPI(mock, cfg.IPsec.SPIIn)
	require.NotNil(t, recorded)
	foreign := *recorded
	foreign.OutputMark = &vnl.XfrmMark{Value: 1}
	i := slices.Index(mock.xfrmStates, recorded)
	mock.xfrmStates[i] = &foreign
	relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), WithIPsecInventory(inv.path))

	require.NoError(t, relaunched.SweepIPsec())

	assert.Equal(t, []*vnl.XfrmState{&foreign}, mock.xfrmStates,
		"the recorded anchor is removed and the foreign SA under the recorded key is never touched")
	assert.Empty(t, mock.xfrmPolicies, "the dropped tunnel's policies are removed")
}

func TestPairEndpoints(t *testing.T) {
	cfg := ipsecConfig()
	local, remote := net.ParseIP(cfg.Local), net.ParseIP(cfg.Remote)
	anchor := espState(local, remote, 0x7001, 0x7001, 0, nil)

	assert.True(t, pairEndpoints(local, remote, anchor), "the anchor's own direction")
	assert.True(t, pairEndpoints(remote, local, anchor), "the reverse direction")
	other := net.ParseIP("192.0.2.77")
	assert.False(t, pairEndpoints(other, local, anchor), "a foreign source")
	assert.False(t, pairEndpoints(local, local, anchor), "one endpoint twice")
}

func TestZeroizeStates(t *testing.T) {
	cfg := ipsecConfig()
	withAead, _ := ipsecStates(cfg, espKey(0x11), espKey(0x22))
	crypt := []byte{1, 2, 3}
	auth := []byte{4, 5}
	states := []vnl.XfrmState{
		*withAead,
		{Crypt: &vnl.XfrmStateAlgo{Key: crypt}, Auth: &vnl.XfrmStateAlgo{Key: auth}},
		{}, // no algorithms at all
	}

	zeroizeStates(states)

	assert.Equal(t, make([]byte, len(states[0].Aead.Key)), states[0].Aead.Key)
	assert.Equal(t, make([]byte, len(crypt)), crypt)
	assert.Equal(t, make([]byte, len(auth)), auth)
	assert.NotPanics(t, func() { zeroizeStates(nil) }, "an empty dump is a no-op")
}

func TestXfrmUnsupported(t *testing.T) {
	assert.True(t, xfrmUnsupported(syscall.EPROTONOSUPPORT))
	assert.True(t, xfrmUnsupported(&ErrIPsecSweepFailed{Op: "list SAs", Cause: syscall.EPROTONOSUPPORT}), "wrapped")
	assert.False(t, xfrmUnsupported(syscall.EPERM))
	assert.False(t, xfrmUnsupported(nil))
}

func TestManager_SweepIPsec_Errors(t *testing.T) {
	cfg := ipsecConfig()
	boom := errors.New("EPERM")
	cases := map[string]struct {
		inject func(m *mockNetlinkOps)
		op     string
	}{
		"list SAs": {
			inject: func(m *mockNetlinkOps) {
				m.xfrmStateListFn = func(int) ([]vnl.XfrmState, error) { return nil, boom }
			},
			op: "list SAs",
		},
		"list policies": {
			inject: func(m *mockNetlinkOps) {
				m.xfrmPolicyListFn = func(int) ([]vnl.XfrmPolicy, error) { return nil, boom }
			},
			op: "list policies",
		},
		"remove policy": {
			inject: func(m *mockNetlinkOps) { m.xfrmPolicyDelFn = func(*vnl.XfrmPolicy) error { return boom } },
			op:     "remove policy",
		},
		"remove SA": {
			inject: func(m *mockNetlinkOps) { m.xfrmStateDelFn = func(*vnl.XfrmState) error { return boom } },
			op:     "remove SA",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			mock, inventory := leftIPsec(t, cfg)
			tc.inject(mock)
			m := newManagerWithOps(testLogger(), mock, inventory)

			err := m.SweepIPsec()

			var sweep *ErrIPsecSweepFailed
			require.True(t, errors.As(err, &sweep), "got %v", err)
			assert.Equal(t, tc.op, sweep.Op)
			assert.ErrorIs(t, err, boom)
			assert.Contains(t, err.Error(), "ipsec sweep: "+tc.op)
		})
	}
}

func TestManager_SweepIPsec_ToleratesWhatIsAlreadyGone(t *testing.T) {
	cfg := ipsecConfig()
	mock, inventory := leftIPsec(t, cfg)
	mock.xfrmPolicyDelFn = func(*vnl.XfrmPolicy) error { return syscall.ENOENT }
	mock.xfrmStateDelFn = func(*vnl.XfrmState) error { return syscall.ESRCH }
	m := newManagerWithOps(testLogger(), mock, inventory)

	assert.NoError(t, m.SweepIPsec(), "a concurrent removal is not a failure")
}

func TestManager_SweepIPsec_KernelWithoutXfrm(t *testing.T) {
	cfg := ipsecConfig()
	anchor, _ := ipsecStates(cfg, nil, nil)
	mock := newMockNetlinkOps()
	mock.xfrmStateListFn = func(int) ([]vnl.XfrmState, error) { return nil, syscall.EPROTONOSUPPORT }
	mock.xfrmPolicyListFn = func(int) ([]vnl.XfrmPolicy, error) {
		return nil, errors.New("policies are not listed when no SA is owned")
	}
	m := newManagerWithOps(testLogger(), mock, recordedInventory(t, anchor))

	assert.NoError(t, m.SweepIPsec(), "a kernel without XFRM holds nothing to sweep")
}

// With nothing recorded, no pair is provably the platform's: the sweep
// returns before it lists the kernel's state, whatever that holds.
func TestManager_SweepIPsec_RemovesNothingWithoutARecord(t *testing.T) {
	for name, opts := range map[string][]Option{
		"no inventory":    nil,
		"empty inventory": {testInventory(t)},
	} {
		t.Run(name, func(t *testing.T) {
			mock, _ := leftIPsec(t, ipsecConfig())
			mock.xfrmStateListFn = func(int) ([]vnl.XfrmState, error) {
				return nil, errors.New("no SA is listed without a record")
			}
			m := newManagerWithOps(testLogger(), mock, opts...)

			require.NoError(t, m.SweepIPsec())
			assert.Len(t, mock.xfrmStates, 2, "the unrecorded pair's SAs stay")
			assert.Len(t, mock.xfrmPolicies, 2, "the unrecorded pair's policies stay")
		})
	}
}

// A foreign pair of the manager's exact shape whose SPI equals its request
// id (Codex P1 on #1149) is not the platform's unless recorded: a local move
// onto its outbound identity retires none of it, and the sweep after leaves
// its inbound SA and policies alone.
func TestManager_EnsureTunnel_RetiresNothingForAnUnrecordedPairWithSPIEqualToReqid(t *testing.T) {
	cfg := ipsecConfig()
	foreign, remote := net.ParseIP("198.51.100.99"), net.ParseIP(cfg.Remote)
	reqid := int(cfg.IPsec.SPIOut)
	mock := newMockNetlinkOps()
	require.NoError(t, mock.recordState(espState(foreign, remote, cfg.IPsec.SPIOut, reqid, 0, espKey(0xCC))))
	require.NoError(t, mock.recordState(espState(remote, foreign, cfg.IPsec.SPIIn, reqid, 0, espKey(0xDD))))
	foreignPolicies := []*vnl.XfrmPolicy{
		espPolicy(foreign, remote, carrierProto(TunnelTypeGRE), vnl.XFRM_DIR_OUT, reqid),
		espPolicy(remote, foreign, carrierProto(TunnelTypeGRE), vnl.XFRM_DIR_IN, reqid),
	}
	mock.xfrmPolicies = slices.Clone(foreignPolicies)
	listed := 0
	mock.xfrmStateListFn = func(int) ([]vnl.XfrmState, error) {
		listed++
		return nil, nil
	}
	manager := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), testInventory(t))

	require.NoError(t, manager.EnsureTunnel(context.Background(), cfg))

	assert.Zero(t, listed, "no ownership lookup for an unrecorded pair")
	assert.NotNil(t, stateBySPIDst(mock, cfg.IPsec.SPIIn, foreign), "the foreign inbound SA is not retired")
	assert.Subset(t, mock.xfrmPolicies, foreignPolicies, "the foreign policies are not retired")

	mock.xfrmStateListFn = nil
	require.NoError(t, manager.SweepIPsec())

	assert.NotNil(t, stateBySPIDst(mock, cfg.IPsec.SPIIn, foreign), "the sweep leaves the foreign inbound SA")
	assert.Subset(t, mock.xfrmPolicies, foreignPolicies, "the sweep leaves the foreign policies")
}

// stateBySPIDst is the SA the mock holds for spi towards dst, or nil.
func stateBySPIDst(mock *mockNetlinkOps, spi uint32, dst net.IP) *vnl.XfrmState {
	for _, state := range mock.xfrmStates {
		if state.Spi == int(spi) && state.Dst.Equal(dst) {
			return state
		}
	}
	return nil
}

func TestManager_RemoveTunnel_IPsecRemovesTheAnchorLast(t *testing.T) {
	cfg := ipsecConfig()
	rec := &recordingXfrm{mockNetlinkOps: newMockNetlinkOps()}
	m := newManagerWithOps(testLogger(), rec, WithKeyProvider(keysFor(cfg)))
	require.NoError(t, m.EnsureTunnel(context.Background(), cfg))

	require.NoError(t, m.RemoveTunnel(context.Background(), cfg.Name))

	require.Len(t, rec.deleted, 5)
	assert.Equal(t, "link:"+cfg.Name, rec.deleted[0], "the carrier goes before its protection")
	assert.Equal(t, []string{"sa:198.51.100.36:" + spiLabel(0x1002), "sa:198.51.100.100:" + spiLabel(0x1001)}, rec.deleted[3:],
		"an interrupted removal leaves the anchor, so the sweep still finds the pair")
}

// A lookup of the outbound identity that fails proves neither that the SA
// there is this tunnel's nor an earlier pair's anchor, so the removal fails
// without deleting it; a retry removes it.
func TestManager_RemoveTunnel_IPsecKeepsTheAnchorWhenItsLookupFails(t *testing.T) {
	cfg := ipsecConfig()
	mock := newMockNetlinkOps()
	m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)))
	require.NoError(t, m.EnsureTunnel(context.Background(), cfg))
	cause := syscall.EPERM
	mock.xfrmStateGetFn = func(*vnl.XfrmState) (*vnl.XfrmState, error) { return nil, cause }

	err := m.RemoveTunnel(context.Background(), cfg.Name)

	var removeErr *ErrTunnelRemoveFailed
	require.ErrorAs(t, err, &removeErr)
	assert.ErrorIs(t, err, cause)
	assert.NotNil(t, stateBySPI(mock, cfg.IPsec.SPIOut), "the outbound SA is not deleted unproven")

	mock.xfrmStateGetFn = nil
	require.NoError(t, m.RemoveTunnel(context.Background(), cfg.Name))
	assert.Empty(t, mock.xfrmStates, "the retry removes the pair")
}

// A start that changes a tunnel's inbound SPI keeps the old inbound SA for
// the sweep. If a later tunnel's ensure then fails, the start rolls this one
// back before the sweep runs: the removal retires the old SA with the pair,
// since dropping the record would leave nothing proving it the platform's.
func TestManager_RemoveTunnel_IPsecRetiresAnInboundSAALaterConfigReplaced(t *testing.T) {
	old := ipsecConfig()
	mock, inv := leftIPsecRecorded(t, old)
	cfg := old
	ipsec := *old.IPsec
	ipsec.SPIIn = 0x2002
	cfg.IPsec = &ipsec
	relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), WithIPsecInventory(inv.path))
	require.NoError(t, relaunched.EnsureTunnel(context.Background(), cfg))
	require.NotNil(t, stateBySPI(mock, old.IPsec.SPIIn), "the ensure keeps the old inbound SA for the sweep")

	require.NoError(t, relaunched.RemoveTunnel(context.Background(), cfg.Name))

	assert.Nil(t, stateBySPI(mock, old.IPsec.SPIIn), "the replaced inbound SA is retired with its pair")
	assert.Empty(t, mock.xfrmStates, "the pair is gone")
	assert.Empty(t, mock.xfrmPolicies, "the pair's policies are gone")
	recorded, err := inv.load()
	require.NoError(t, err)
	assert.Empty(t, recorded, "the record goes once every member it names is gone")
}

// A tunnel of another name that reuses the pair leaves the earlier carrier
// and its policies recorded; rolling the new tunnel back retires them too.
func TestManager_RemoveTunnel_IPsecRetiresTheRecordedCarrierOfAnEarlierName(t *testing.T) {
	old := ipsecConfig()
	mock, inv := leftIPsecRecorded(t, old)
	rec := &recordingXfrm{mockNetlinkOps: mock}
	replacement := old
	replacement.Name, replacement.Type = "ipip-new", TunnelTypeIPIP
	relaunched := newManagerWithOps(testLogger(), rec, WithKeyProvider(keysFor(replacement)), WithIPsecInventory(inv.path))
	require.NoError(t, relaunched.EnsureTunnel(context.Background(), replacement))
	require.Contains(t, rec.links, old.Name, "the earlier carrier is still up")

	require.NoError(t, relaunched.RemoveTunnel(context.Background(), replacement.Name))

	assert.NotContains(t, rec.links, old.Name, "the earlier carrier is retired with the pair")
	assert.NotContains(t, rec.links, replacement.Name, "the removed tunnel's carrier is gone")
	assert.Empty(t, rec.xfrmPolicies, "the earlier carrier's policies are retired too")
	assert.Empty(t, rec.xfrmStates, "the pair is gone")
	require.NotEmpty(t, rec.deleted)
	assert.Equal(t, "sa:198.51.100.100:"+spiLabel(0x1001), rec.deleted[len(rec.deleted)-1], "the anchor goes last")
	recorded, err := inv.load()
	require.NoError(t, err)
	assert.Empty(t, recorded)
}

// A replacement on the same carrier protocol, endpoints and ESP pair shares
// the earlier carrier's policies. Rolling back its failed start retires that
// carrier before any policy goes; when the carrier will not go, the policies
// stay (RFC 4301 §4.4.1) and the failure is reported.
func TestManager_EnsureTunnel_IPsecRollbackKeepsSharedPoliciesWhileTheEarlierCarrierStays(t *testing.T) {
	old := ipsecConfig()
	mock, inv := leftIPsecRecorded(t, old)
	rec := &recordingXfrm{mockNetlinkOps: mock}
	replacement := old
	replacement.Name = "gre-new"
	mock.linkSetUpFn = func(link vnl.Link) error {
		if link.Attrs().Name == replacement.Name {
			return errors.New("netlink busy")
		}
		return nil
	}
	mock.linkDelFn = func(link vnl.Link) error {
		name := link.Attrs().Name
		if name == old.Name {
			return errors.New("netlink busy")
		}
		mock.mu.Lock()
		defer mock.mu.Unlock()
		delete(mock.links, name)
		delete(mock.addrs, name)
		return nil
	}
	relaunched := newManagerWithOps(testLogger(), rec, WithKeyProvider(keysFor(replacement)), WithIPsecInventory(inv.path))

	err := relaunched.EnsureTunnel(context.Background(), replacement)

	var removeErr *ErrTunnelRemoveFailed
	require.ErrorAs(t, err, &removeErr, "the unfinished rollback is reported")
	var sweepErr *ErrIPsecSweepFailed
	require.ErrorAs(t, err, &sweepErr)
	assert.Equal(t, "remove carrier", sweepErr.Op)
	assert.Contains(t, mock.links, old.Name, "the earlier carrier is still up")
	assert.Len(t, mock.xfrmPolicies, 2, "the shared policies still protect it")

	mock.linkDelFn = nil
	rec.deleted = nil
	err = relaunched.EnsureTunnel(context.Background(), replacement)

	require.Error(t, err, "the replacement still fails to start")
	assert.False(t, errors.As(err, &removeErr), "the rollback finished")
	assert.NotContains(t, mock.links, old.Name, "the earlier carrier is retired")
	assert.Empty(t, mock.xfrmPolicies, "the policies go once nothing they protect is left")
	carrier, policy := slices.Index(rec.deleted, "link:"+old.Name), slices.IndexFunc(rec.deleted, func(d string) bool {
		return strings.HasPrefix(d, "policy:")
	})
	require.GreaterOrEqual(t, carrier, 0)
	require.GreaterOrEqual(t, policy, 0)
	assert.Less(t, carrier, policy, "the carrier is retired before its policies")
}

// A replacement that fails to bind to its uplink is torn down. The teardown
// retires the earlier carrier sharing its policies before any policy goes;
// when that carrier will not go, the policies stay and the failure is
// reported with the bind failure, not discarded.
func TestManager_EnsureTunnel_IPsecBindFailureReportsAnUnfinishedTeardown(t *testing.T) {
	old := ipsecConfig()
	mock, inv := leftIPsecRecorded(t, old)
	mock.links["eth6"] = &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "eth6", Index: 6}}
	up := newUplinkManagerWithOps(testLogger(), mock)
	require.NoError(t, up.EnsureUplink(context.Background(), UplinkConfig{
		Name: "isp-a", Interface: "eth6", Table: 101, GatewayV4: "198.51.100.38", Addresses: []string{"198.51.100.36/29"},
	}))
	rec := &recordingXfrm{mockNetlinkOps: mock}
	replacement := old
	replacement.Name, replacement.Uplink = "gre-new", "isp-a"
	bindCause := errors.New("EINVAL")
	mock.ruleAddFn = func(*vnl.Rule) error { return bindCause }
	retireCause := errors.New("netlink busy")
	mock.linkDelFn = func(link vnl.Link) error {
		name := link.Attrs().Name
		if name == old.Name {
			return retireCause
		}
		mock.mu.Lock()
		defer mock.mu.Unlock()
		delete(mock.links, name)
		delete(mock.addrs, name)
		return nil
	}
	relaunched := newManagerWithOps(testLogger(), rec, WithKeyProvider(keysFor(replacement)),
		WithIPsecInventory(inv.path), WithUplinks(up))

	err := relaunched.EnsureTunnel(context.Background(), replacement)

	var createErr *ErrTunnelCreateFailed
	require.ErrorAs(t, err, &createErr, "the bind failure is reported")
	assert.ErrorIs(t, err, bindCause)
	var removeErr *ErrTunnelRemoveFailed
	require.ErrorAs(t, err, &removeErr, "the unfinished teardown is reported")
	var sweepErr *ErrIPsecSweepFailed
	require.ErrorAs(t, err, &sweepErr)
	assert.Equal(t, "remove carrier", sweepErr.Op)
	assert.ErrorIs(t, err, retireCause)
	assert.Contains(t, mock.links, old.Name, "the earlier carrier is still up")
	assert.NotContains(t, mock.links, replacement.Name, "the replacement's carrier is torn down")
	assert.Len(t, mock.xfrmPolicies, 2, "the shared policies still protect the earlier carrier")

	mock.linkDelFn = nil
	rec.deleted = nil
	err = relaunched.EnsureTunnel(context.Background(), replacement)

	require.ErrorAs(t, err, &createErr, "the replacement still fails to bind")
	assert.False(t, errors.As(err, &removeErr), "the teardown finished")
	assert.NotContains(t, mock.links, old.Name, "the earlier carrier is retired")
	assert.Empty(t, mock.xfrmPolicies, "the policies go once nothing they protect is left")
	carrier, policy := slices.Index(rec.deleted, "link:"+old.Name), slices.IndexFunc(rec.deleted, func(d string) bool {
		return strings.HasPrefix(d, "policy:")
	})
	require.GreaterOrEqual(t, carrier, 0)
	require.GreaterOrEqual(t, policy, 0)
	assert.Less(t, carrier, policy, "the carrier is retired before its policies")
}

// A carrier the teardown cannot delete keeps its protection: no policy is
// touched, and the failure is reported with the bind failure.
func TestManager_EnsureTunnel_IPsecBindFailureKeepsPoliciesWhileItsCarrierStays(t *testing.T) {
	cfg := ipsecConfig()
	cfg.Uplink = "isp-a"
	mock := newMockNetlinkOps()
	mock.links["eth6"] = &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "eth6", Index: 6}}
	up := newUplinkManagerWithOps(testLogger(), mock)
	require.NoError(t, up.EnsureUplink(context.Background(), UplinkConfig{
		Name: "isp-a", Interface: "eth6", Table: 101, GatewayV4: "198.51.100.38", Addresses: []string{"198.51.100.36/29"},
	}))
	mock.ruleAddFn = func(*vnl.Rule) error { return errors.New("EINVAL") }
	delCause := errors.New("netlink busy")
	mock.linkDelFn = func(vnl.Link) error { return delCause }
	m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), WithUplinks(up))

	err := m.EnsureTunnel(context.Background(), cfg)

	var createErr *ErrTunnelCreateFailed
	require.ErrorAs(t, err, &createErr)
	var removeErr *ErrTunnelRemoveFailed
	require.ErrorAs(t, err, &removeErr)
	assert.Equal(t, cfg.Name, removeErr.Name)
	assert.ErrorIs(t, err, delCause)
	assert.Contains(t, mock.links, cfg.Name, "the carrier is still up")
	assert.Len(t, mock.xfrmPolicies, 2, "its policies still protect it")
	assert.Len(t, mock.xfrmStates, 2, "its SAs stay")
}

// A carrier that fails to come up after it was added is rolled back with its
// protection: neither the link nor its policies and SAs are left behind.
func TestManager_EnsureTunnel_IPsecCarrierFailureRemovesTheHalfMadeCarrier(t *testing.T) {
	cfg := ipsecConfig()
	mock := newMockNetlinkOps()
	cause := errors.New("netlink busy")
	mock.linkSetUpFn = func(vnl.Link) error { return cause }
	rec := &recordingXfrm{mockNetlinkOps: mock}
	m := newManagerWithOps(testLogger(), rec, WithKeyProvider(keysFor(cfg)))

	err := m.EnsureTunnel(context.Background(), cfg)

	assert.ErrorIs(t, err, cause)
	assert.NotContains(t, mock.links, cfg.Name, "the half-made carrier is removed")
	assert.Empty(t, mock.xfrmPolicies, "its policies are removed")
	assert.Empty(t, mock.xfrmStates, "its SAs are removed")
	policy := slices.IndexFunc(rec.deleted, func(d string) bool { return strings.HasPrefix(d, "policy:") })
	require.GreaterOrEqual(t, policy, 0)
	assert.Less(t, slices.Index(rec.deleted, "link:"+cfg.Name), policy, "the carrier goes before its protection")
	assert.GreaterOrEqual(t, slices.Index(rec.deleted, "link:"+cfg.Name), 0)
}

// A member the removal cannot retire keeps the anchor and the record, so the
// next start's sweep still proves the rest the platform's.
func TestManager_RemoveTunnel_IPsecKeepsTheRecordWhileAReplacedMemberStays(t *testing.T) {
	old := ipsecConfig()
	mock, inv := leftIPsecRecorded(t, old)
	cfg := old
	ipsec := *old.IPsec
	ipsec.SPIIn = 0x2002
	cfg.IPsec = &ipsec
	relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), WithIPsecInventory(inv.path))
	require.NoError(t, relaunched.EnsureTunnel(context.Background(), cfg))
	stale := stateBySPI(mock, old.IPsec.SPIIn)
	require.NotNil(t, stale)
	eperm := errors.New("EPERM")
	mock.xfrmStateDelFn = func(s *vnl.XfrmState) error {
		if s.Spi == stale.Spi && s.Dst.Equal(stale.Dst) {
			return eperm
		}
		return syscall.ESRCH
	}

	err := relaunched.RemoveTunnel(context.Background(), cfg.Name)

	var rf *ErrTunnelRemoveFailed
	require.True(t, errors.As(err, &rf), "got %v", err)
	require.True(t, errors.Is(err, eperm), "the kernel's error is the cause: %v", err)
	recorded, err := inv.load()
	require.NoError(t, err)
	out, _ := ipsecStates(cfg, nil, nil)
	require.Contains(t, recorded, recordOf(out), "the record stays while a member remains")
	assert.Contains(t, recorded[recordOf(out)].SAs, saRecordOf(stale), "the replaced SA stays recorded")

	mock.xfrmStateDelFn = nil
	next := newManagerWithOps(testLogger(), mock, WithIPsecInventory(inv.path))
	require.NoError(t, next.SweepIPsec())
	assert.Empty(t, mock.xfrmStates, "the next sweep retires the rest")
}
