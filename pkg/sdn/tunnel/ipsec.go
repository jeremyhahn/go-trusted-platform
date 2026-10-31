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
	"crypto/subtle"
	"errors"
	"log/slog"
	"net"
	"slices"
	"syscall"

	vnl "github.com/vishvananda/netlink"
)

// ipsecReqid derives the XFRM request id that ties a tunnel's policies to
// its SAs from the outbound SPI, which the configuration already requires
// to be unique per tunnel.
func ipsecReqid(cfg *IPsecConfig) int {
	return int(cfg.SPIOut)
}

// carrierProto is the IP protocol the carrier tunnel emits, which the
// XFRM selectors match so only tunnel traffic is protected.
func carrierProto(tunnelType string) vnl.Proto {
	if tunnelType == TunnelTypeIPIP {
		return vnl.Proto(4) // IPPROTO_IPIP
	}
	return vnl.Proto(47) // IPPROTO_GRE
}

// hostNet returns ip as a single-host network.
func hostNet(ip net.IP) *net.IPNet {
	if ip.To4() != nil {
		return &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

// espState builds one transport-mode ESP SA. key is the 36-byte
// AES-256-GCM material (key || salt); the caller zeroizes it afterwards.
func espState(src, dst net.IP, spi uint32, reqid int, replay int, key []byte) *vnl.XfrmState {
	return &vnl.XfrmState{
		Src:          src,
		Dst:          dst,
		Proto:        vnl.XFRM_PROTO_ESP,
		Mode:         vnl.XFRM_MODE_TRANSPORT,
		Spi:          int(spi),
		Reqid:        reqid,
		ReplayWindow: replay,
		ESN:          true,
		Aead: &vnl.XfrmStateAlgo{
			Name:   espGCMAlgo,
			Key:    key,
			ICVLen: espGCMICVBits,
		},
	}
}

// espPolicy builds the XFRM policy that sends the carrier's traffic between
// the two endpoints through the ESP SA with reqid.
func espPolicy(src, dst net.IP, proto vnl.Proto, dir vnl.Dir, reqid int) *vnl.XfrmPolicy {
	return &vnl.XfrmPolicy{
		Src:    hostNet(src),
		Dst:    hostNet(dst),
		Proto:  proto,
		Dir:    dir,
		Action: vnl.XFRM_POLICY_ALLOW,
		Tmpls: []vnl.XfrmPolicyTmpl{{
			Src:   src,
			Dst:   dst,
			Proto: vnl.XFRM_PROTO_ESP,
			Mode:  vnl.XFRM_MODE_TRANSPORT,
			Reqid: reqid,
		}},
	}
}

// ipsecStates returns the outbound and inbound SAs for cfg with the given
// key material (out, in).
func ipsecStates(config TunnelConfig, outKey, inKey []byte) (out, in *vnl.XfrmState) {
	local := net.ParseIP(config.Local)
	remote := net.ParseIP(config.Remote)
	reqid := ipsecReqid(config.IPsec)
	replay := config.IPsec.effectiveReplayWindow()
	out = espState(local, remote, config.IPsec.SPIOut, reqid, replay, outKey)
	in = espState(remote, local, config.IPsec.SPIIn, reqid, replay, inKey)
	return out, in
}

// ipsecPolicies returns the out and in policies for cfg.
func ipsecPolicies(config TunnelConfig) (out, in *vnl.XfrmPolicy) {
	local := net.ParseIP(config.Local)
	remote := net.ParseIP(config.Remote)
	reqid := ipsecReqid(config.IPsec)
	proto := carrierProto(config.Type)
	out = espPolicy(local, remote, proto, vnl.XFRM_DIR_OUT, reqid)
	in = espPolicy(remote, local, proto, vnl.XFRM_DIR_IN, reqid)
	return out, in
}

// reconcileIPsec makes the kernel hold this tunnel's SAs and policies:
// whatever is missing is added, whatever differs is replaced, and whatever
// matches is kept, so a relaunch over the XFRM a killed predecessor left
// keeps its live SAs and their sequence numbers. On a fresh install every
// object is missing and this is a plain install. The SAs come first and the
// policies last, so no policy ever selects traffic into an SA that does not
// exist (which the kernel would drop — fail closed, but a black hole). Key
// material is zeroized once the kernel holds it or it has been compared.
func (m *Manager) reconcileIPsec(ctx context.Context, config TunnelConfig) error {
	outKey, err := fetchKey(ctx, m.keys, config.Name, config.IPsec.KeyRef, espGCMKeyLen)
	if err != nil {
		return err
	}
	defer zeroize(outKey)
	inKey, err := fetchKey(ctx, m.keys, config.Name, config.IPsec.effectivePeerKeyRef(), espGCMKeyLen)
	if err != nil {
		return err
	}
	defer zeroize(inKey)

	out, in := ipsecStates(config, outKey, inKey)
	if err := m.retireMovedPair(out); err != nil {
		return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
	}
	polOut, polIn := ipsecPolicies(config)
	// The pair, its policies and its carrier are recorded before any goes
	// in, so the record never lags the kernel: it is what proves them the
	// platform's to a later sweep.
	if err := m.inventory.add(out, in, config.Name, polOut, polIn); err != nil {
		return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
	}
	for _, want := range []*vnl.XfrmState{out, in} {
		if err := m.reconcileState(want); err != nil {
			return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
		}
	}
	for _, want := range []*vnl.XfrmPolicy{polOut, polIn} {
		if err := m.reconcilePolicy(want); err != nil {
			return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
		}
	}
	return nil
}

// reconcileState keeps an installed SA that matches want, replaces one that
// differs and adds a missing one. A differing SA is deleted and added, so
// its key and algorithm are replaced whole. Only an SA of the shape espState
// builds (ownedSAShape, the check the sweep's ownedIPsec makes) is the
// platform's to keep or replace: any other SA at want's key is another
// installer's and is refused with ErrIPsecForeignSA, never deleted.
func (m *Manager) reconcileState(want *vnl.XfrmState) error {
	have, err := m.nl.XfrmStateGet(want)
	if err != nil && !xfrmMissing(err) {
		return err
	}
	if err == nil {
		owned := ownedSAShape(have)
		matches := owned && espStateMatches(have, want)
		if have.Aead != nil {
			zeroize(have.Aead.Key)
		}
		if !owned {
			return &ErrIPsecForeignSA{Dst: want.Dst.String(), SPI: want.Spi}
		}
		if matches {
			return nil
		}
		if err := m.nl.XfrmStateDel(have); err != nil {
			return err
		}
	}
	return m.nl.XfrmStateAdd(want)
}

// retireMovedPair removes the pair an earlier incarnation installed under the
// same outbound SA identity (destination and SPI) from another local
// endpoint: reconcileState is about to replace that outbound SA, which is the
// pair's anchor (see ownedIPsec), and once it is gone the old inbound SA,
// policies and any carrier on the old endpoints are no longer provably this
// manager's, so no later sweep could remove them. They go now, in
// SweepIPsec's order with the anchor last, so a removal cut short leaves the
// anchor and the next start retires the rest. The caller holds m.mu.
func (m *Manager) retireMovedPair(want *vnl.XfrmState) error {
	have, err := m.nl.XfrmStateGet(want)
	if err != nil {
		if xfrmMissing(err) {
			return nil
		}
		return err
	}
	if have.Aead != nil {
		zeroize(have.Aead.Key)
	}
	if !ownedSAShape(have) || have.Spi != have.Reqid || pairEndpoints(want.Src, want.Dst, have) {
		return nil
	}
	recorded, err := m.inventory.load()
	if err != nil {
		return &ErrIPsecSweepFailed{Op: "read inventory", Cause: err}
	}
	if _, ok := recorded[recordOf(have)]; !ok {
		return nil
	}
	states, err := m.nl.XfrmStateList(vnl.FAMILY_ALL)
	if err != nil {
		return &ErrIPsecSweepFailed{Op: "list SAs", Cause: err}
	}
	defer zeroizeStates(states)
	pair := pairOf(ownedIPsec(states, recorded), have.Reqid, have.Src, have.Dst)
	if pair == nil {
		return nil
	}
	return m.sweepOwnedLocked(map[int][]*ownedPair{have.Reqid: {pair}}, "")
}

// reconcilePolicy keeps an installed policy that matches want and otherwise
// installs want; XFRM_MSG_UPDPOLICY adds a missing policy and replaces a
// differing one in place, with no window in which the selector is open. Only
// a policy of the shape espPolicy builds (ownedPolicyShape, the check the
// sweep's ownedPolicy makes) is the platform's to keep or replace: any other
// policy at want's key is another installer's and is refused with
// ErrIPsecForeignPolicy, so reconcile and sweep agree on what is the
// platform's.
func (m *Manager) reconcilePolicy(want *vnl.XfrmPolicy) error {
	have, err := m.nl.XfrmPolicyGet(want)
	if err != nil && !xfrmMissing(err) {
		return err
	}
	if err == nil {
		if !ownedPolicyShape(have) {
			return &ErrIPsecForeignPolicy{Src: want.Src.String(), Dst: want.Dst.String(), Dir: want.Dir.String()}
		}
		if espPolicyMatches(have, want) {
			return nil
		}
	}
	return m.nl.XfrmPolicyUpdate(want)
}

// removePolicy deletes the policy at p's key when it is of the shape
// espPolicy builds, and leaves any other installer's policy there: a
// rollback after reconcilePolicy refused a foreign policy must not delete
// it. A policy already gone counts as removed.
func (m *Manager) removePolicy(p *vnl.XfrmPolicy) error {
	have, err := m.nl.XfrmPolicyGet(p)
	if xfrmMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !ownedPolicyShape(have) {
		return nil
	}
	if err := m.nl.XfrmPolicyDel(p); err != nil && !xfrmMissing(err) {
		return err
	}
	return nil
}

// xfrmMissing reports whether err is the kernel's answer for an SA (ESRCH)
// or a policy (ENOENT) that is not installed.
func xfrmMissing(err error) bool {
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENOENT)
}

// espStateMatches reports whether an installed SA is the one want describes:
// the same endpoints, SPI, mode, request id, replay protection and AEAD.
// The keys are compared in constant time. A kernel in lockdown
// confidentiality mode returns the key zeroed; such an SA never matches and
// is replaced, as before adoption existed.
func espStateMatches(have, want *vnl.XfrmState) bool {
	if have.Aead == nil || have.Encap != nil || have.Mark != nil {
		return false
	}
	return have.Src.Equal(want.Src) && have.Dst.Equal(want.Dst) &&
		have.Proto == want.Proto && have.Spi == want.Spi && have.Mode == want.Mode &&
		have.Reqid == want.Reqid && have.ESN == want.ESN && have.ReplayWindow == want.ReplayWindow &&
		have.Aead.Name == want.Aead.Name && have.Aead.ICVLen == want.Aead.ICVLen &&
		subtle.ConstantTimeCompare(have.Aead.Key, want.Aead.Key) == 1
}

// espPolicyMatches reports whether an installed policy found by want's
// selector and direction is the one espPolicy built for want: of the owned
// shape (ownedPolicyShape, which refuses an optional template, since that
// lets unencrypted carrier traffic through) and with want's template.
func espPolicyMatches(have, want *vnl.XfrmPolicy) bool {
	if !ownedPolicyShape(have) || have.Action != want.Action {
		return false
	}
	h, w := have.Tmpls[0], want.Tmpls[0]
	return h.Src.Equal(w.Src) && h.Dst.Equal(w.Dst) && h.Proto == w.Proto && h.Mode == w.Mode &&
		h.Reqid == w.Reqid
}

// adoptIPsec adopts the carrier a killed predecessor left when it matches
// the configuration, and reconciles its protection against the kernel's.
// A carrier that differs is not adopted; it is recreated, and the matching
// SAs still survive because the fresh install reconciles too.
func (m *Manager) adoptIPsec(ctx context.Context, link vnl.Link, config TunnelConfig) (bool, error) {
	if !linkMatches(link, config) {
		return false, nil
	}
	ok, err := m.hasTunnelAddresses(link, config)
	if err != nil || !ok {
		return false, err
	}
	if err := m.reconcileIPsec(ctx, config); err != nil {
		// A foreign policy at the pair's key is never overwritten, so the
		// carrier cannot be proven protected: an optional template, say,
		// admits it in the clear (RFC 4301 §4.4.1). The carrier goes, and
		// the foreign policy stays (removePolicy leaves it).
		var foreign *ErrIPsecForeignPolicy
		if errors.As(err, &foreign) {
			return false, withRollback(err, m.teardownTransport(config))
		}
		return false, err
	}
	return true, nil
}

// removeIPsecStates deletes both SAs, the outbound one last: it is the pair's
// anchor (see ownedIPsec), the only evidence a later sweep has that the rest
// of the pair is the platform's. A state already gone counts as removed. Any
// other failure to remove the inbound SA returns before the anchor is
// touched, and a failure to remove the anchor keeps its inventory record, so
// what a removal cut short leaves stays recognisable to the next sweep. Once
// the anchor is gone the pair's record is dropped. Another installer's SA at
// either key (one not of ownedSAShape, which reconcileState refused) is left
// where it is.
func (m *Manager) removeIPsecStates(config TunnelConfig) error {
	out, in := ipsecStates(config, nil, nil)
	if err := m.removeState(in); err != nil {
		return err
	}
	// An outbound SA under this identity from another local endpoint is an
	// earlier pair's anchor that retireMovedPair has not retired; it stays,
	// so the next start still recognises and retires that pair. A lookup
	// that fails proves neither, so nothing is deleted under the identity.
	have, err := m.nl.XfrmStateGet(out)
	if err != nil && !xfrmMissing(err) {
		return err
	}
	if err == nil {
		if have.Aead != nil {
			zeroize(have.Aead.Key)
		}
		if !have.Src.Equal(out.Src) || !ownedSAShape(have) {
			return m.inventory.remove(out)
		}
	}
	if err := m.nl.XfrmStateDel(out); err != nil && !xfrmMissing(err) {
		return err
	}
	return m.inventory.remove(out)
}

// removeState deletes the SA at s's key when it is of the shape espState
// builds, and leaves any other installer's SA there, as removePolicy does
// for policies. An SA already gone counts as removed.
func (m *Manager) removeState(s *vnl.XfrmState) error {
	have, err := m.nl.XfrmStateGet(s)
	if xfrmMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	owned := ownedSAShape(have)
	if have.Aead != nil {
		zeroize(have.Aead.Key)
	}
	if !owned {
		return nil
	}
	if err := m.nl.XfrmStateDel(s); err != nil && !xfrmMissing(err) {
		return err
	}
	return nil
}

// removeIPsec takes the policies out before the SAs, the reverse of install.
// A policy or state already gone counts as removed, and another installer's
// policy at a pair's key is left (removePolicy). If a policy cannot be
// removed the SAs and the inventory record stay, so the anchor still proves
// the leftover policy the platform's to the next sweep (see ownedPolicy).
func (m *Manager) removeIPsec(config TunnelConfig) error {
	// Carriers first: a recorded carrier of an earlier name on the same
	// endpoints and ESP pair is protected by these very SPD entries
	// (RFC 4301 §4.4.1). Deleting them first would let that carrier send in
	// the clear, and leave it so if retiring it then failed. A carrier that
	// cannot be retired keeps the policies.
	if err := m.retireRecordedPair(config); err != nil {
		return &ErrTunnelRemoveFailed{Name: config.Name, Cause: err}
	}
	polOut, polIn := ipsecPolicies(config)
	for _, p := range []*vnl.XfrmPolicy{polOut, polIn} {
		if err := m.removePolicy(p); err != nil {
			return &ErrTunnelRemoveFailed{Name: config.Name, Cause: err}
		}
	}
	if err := m.removeIPsecStates(config); err != nil {
		return &ErrTunnelRemoveFailed{Name: config.Name, Cause: err}
	}
	return nil
}

// retireRecordedPair retires everything the inventory records under the
// pair config anchors, before the pair's anchor and record go: an inbound SA
// a later configuration replaced, a policy or a carrier of an earlier name.
// The current configuration's state is only part of what the pair records,
// and once the record is dropped nothing proves the rest the platform's, so a
// rollback before the start's sweep would orphan it. config no longer names
// its own state here, since it is being removed; another managed tunnel still
// naming the pair keeps it. A failure returns before the record is touched,
// so the next sweep can still retire what is left.
func (m *Manager) retireRecordedPair(config TunnelConfig) error {
	out, _ := ipsecStates(config, nil, nil)
	recorded, err := m.inventory.load()
	if err != nil {
		return &ErrIPsecSweepFailed{Op: "read inventory", Cause: err}
	}
	entry, ok := recorded[recordOf(out)]
	if !ok {
		return nil
	}
	states, err := m.nl.XfrmStateList(vnl.FAMILY_ALL)
	if err != nil {
		if xfrmUnsupported(err) {
			return nil
		}
		return &ErrIPsecSweepFailed{Op: "list SAs", Cause: err}
	}
	defer zeroizeStates(states)
	owned := ownedIPsec(states, map[ipsecPairRecord]*ipsecInventoryEntry{entry.ipsecPairRecord: entry})
	return m.sweepOwnedLocked(owned, config.Name)
}

// saKey identifies an SA the way the kernel does for ESP: destination and SPI.
type saKey struct {
	dst string
	spi int
}

func keyOfSA(s *vnl.XfrmState) saKey {
	return saKey{dst: s.Dst.String(), spi: s.Spi}
}

// policyKey identifies a policy by its selector and direction, the identity
// XFRM_MSG_UPDPOLICY replaces in place.
type policyKey struct {
	src, dst string
	proto    vnl.Proto
	dir      vnl.Dir
}

func keyOfPolicy(p *vnl.XfrmPolicy) policyKey {
	return policyKey{src: p.Src.String(), dst: p.Dst.String(), proto: p.Proto, dir: p.Dir}
}

// ownedPair is the ESP state of one tunnel as the kernel holds it: the
// anchor (the outbound SA, whose SPI is the request id) and every SA under
// the same request id on the anchor's endpoints that the inventory records
// installing, the anchor included. The carriers are the names of the links,
// and the policies the identities of the policies, the inventory records for
// the pair. A pair whose anchor the kernel no longer holds (a stop between
// reconcileState's delete of a differing outbound SA and its replacement)
// keeps the recorded anchor (recordedAnchor) with installed false: its other
// recorded objects are still swept on the recorded endpoints, and the
// stand-in anchor itself is never deleted.
type ownedPair struct {
	anchor    *vnl.XfrmState
	installed bool
	members   []*vnl.XfrmState
	carriers  []string
	policies  []ipsecPolicyRecord
}

// ownedSAShape reports whether s has the shape espState builds: transport
// ESP with the AES-GCM AEAD, no mark and no UDP encapsulation.
func ownedSAShape(s *vnl.XfrmState) bool {
	return s.Proto == vnl.XFRM_PROTO_ESP && s.Mode == vnl.XFRM_MODE_TRANSPORT &&
		s.Mark == nil && s.Encap == nil && s.Aead != nil &&
		s.Aead.Name == espGCMAlgo && s.Aead.ICVLen == espGCMICVBits &&
		stateFieldsUnset(s)
}

// stateFieldsUnset reports whether s leaves unset every field espState
// never sets that binds an SA to other traffic: the output mark, the xfrm
// interface id, the SA direction, the per-CPU number, the extra flags and
// the selector's addresses, interface, ports and protocol. The kernel looks an SA up by
// destination, SPI, protocol and mark alone, so one carrying any of these is
// another installer's SA that replaced the platform's under the same key.
func stateFieldsUnset(s *vnl.XfrmState) bool {
	if s.OutputMark != nil || s.Ifid != 0 || s.SADir != 0 || s.Pcpunum != nil {
		return false
	}
	if s.DontEncapDSCP || s.OSeqMayWrap {
		return false
	}
	sel := s.Selector
	if sel == nil {
		return true
	}
	return selectorAddrUnset(sel.Src) && selectorAddrUnset(sel.Dst) &&
		sel.Ifindex == 0 && sel.SrcPort == 0 && sel.DstPort == 0 && sel.Proto == 0
}

// selectorAddrUnset reports whether a selector address is the wildcard
// espState leaves it as. netlink reports an unset selector address, an
// all-zero address with a zero prefix length, as 0.0.0.0/0 or ::/0 by the
// selector's family; a struct built in-process may leave it nil.
func selectorAddrUnset(n *net.IPNet) bool {
	if n == nil {
		return true
	}
	ones, bits := n.Mask.Size()
	return ones == 0 && bits != 0 && n.IP.IsUnspecified()
}

// pairEndpoints reports whether src and dst are the anchor's endpoints in
// either direction.
func pairEndpoints(src, dst net.IP, anchor *vnl.XfrmState) bool {
	return (src.Equal(anchor.Src) && dst.Equal(anchor.Dst)) ||
		(src.Equal(anchor.Dst) && dst.Equal(anchor.Src))
}

// ownedIPsec picks out of the kernel's SAs the ones this manager installed,
// grouped by request id and endpoint pair. The manager ties a pair together
// with the outbound SPI as request id (ipsecReqid), so its outbound SA is the
// one SA whose SPI equals its request id; an IKE daemon allocates request ids
// and SPIs independently. One request id can hold several pairs: a tunnel
// whose remote moved while SPIOut stayed leaves the old pair beside the new
// one, and each is matched and swept on its own endpoints; a local move
// replaces the old pair's anchor, so the ensure retires that pair first
// (retireMovedPair). Shape and request id alone prove nothing: another
// installer may add an identical transport AES-GCM pair with its SPI equal to
// its request id. So an anchor counts only when the platform's inventory
// records its request id and endpoints (ipsecInventory). A group without a
// recorded anchor is not provably this manager's and is left alone, as is
// any SA off every anchor's endpoints. The pairs come from the inventory, not
// from the kernel: every recorded pair is one, whether or not its outbound SA
// is still installed, so a stop that removed only the anchor does not strand
// the pair's inbound SA, policies and carrier. Within a pair, too, an SA counts only
// when the inventory records its identity: an IKE daemon may use the anchor's
// request id for an SA of its own between the same hosts.
func ownedIPsec(states []vnl.XfrmState, recorded map[ipsecPairRecord]*ipsecInventoryEntry) map[int][]*ownedPair {
	owned := make(map[int][]*ownedPair)
	entries := make(map[*ownedPair]*ipsecInventoryEntry)
	for _, entry := range sortedEntries(recorded) {
		if pairOf(owned, entry.Reqid, net.ParseIP(entry.Src), net.ParseIP(entry.Dst)) != nil {
			continue
		}
		pair := &ownedPair{anchor: recordedAnchor(entry.ipsecPairRecord), carriers: entry.Carriers, policies: entry.Policies}
		owned[entry.Reqid] = append(owned[entry.Reqid], pair)
		entries[pair] = entry
	}
	for i := range states {
		s := &states[i]
		pair := pairOf(owned, s.Reqid, s.Src, s.Dst)
		if pair != nil && !pair.installed && ownedSAShape(s) && s.Reqid != 0 && s.Spi == s.Reqid &&
			recordOf(s) == entries[pair].ipsecPairRecord {
			pair.anchor, pair.installed = s, true
		}
	}
	for i := range states {
		s := &states[i]
		pair := pairOf(owned, s.Reqid, s.Src, s.Dst)
		if pair != nil && ownedSAShape(s) && (s == pair.anchor || entries[pair].ownsSA(s)) {
			pair.members = append(pair.members, s)
		}
	}
	return owned
}

// sortedEntries is the inventory's entries in the order the file keeps them,
// so the pairs built from them do not depend on map iteration.
func sortedEntries(recorded map[ipsecPairRecord]*ipsecInventoryEntry) []*ipsecInventoryEntry {
	entries := make([]*ipsecInventoryEntry, 0, len(recorded))
	for _, entry := range recorded {
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(a, b *ipsecInventoryEntry) int { return compareEntries(*a, *b) })
	return entries
}

// recordedAnchor is the outbound SA the inventory records for a pair, as
// espState builds it without a key. It stands in for an anchor the kernel no
// longer holds, so the pair's endpoints and request id still match its
// inbound SA, policies and carriers; it is never installed or deleted.
func recordedAnchor(rec ipsecPairRecord) *vnl.XfrmState {
	return &vnl.XfrmState{
		Src:   net.ParseIP(rec.Src),
		Dst:   net.ParseIP(rec.Dst),
		Proto: vnl.XFRM_PROTO_ESP,
		Mode:  vnl.XFRM_MODE_TRANSPORT,
		Spi:   rec.Reqid,
		Reqid: rec.Reqid,
	}
}

// pairOf returns the owned pair under reqid whose anchor sits on src and dst,
// or nil.
func pairOf(owned map[int][]*ownedPair, reqid int, src, dst net.IP) *ownedPair {
	for _, pair := range owned[reqid] {
		if pairEndpoints(src, dst, pair.anchor) {
			return pair
		}
	}
	return nil
}

// ownedPolicy returns the owned pair p protects when p is a policy espPolicy
// built for that pair and the inventory records installing it, or nil: an
// allow policy between two hosts for the carrier protocol, with one
// transport ESP template under the pair's request id and on its endpoints,
// whose selector and template the pair's record names. Shape, request id and
// endpoints alone prove nothing: another installer may protect an IPIP
// carrier between the same hosts under the request id of the platform's GRE
// pair. Templateless policies (the overlay's block policies) and any other
// installer's policies never match.
//
// Every selector and template field espPolicy leaves unset must be unset on
// p too (policyFieldsUnset): the kernel keys a policy on its whole selector,
// mark and interface id, so an interface-scoped or port-scoped policy with
// the pair's endpoints and template is a different policy, and another
// installer's.
func ownedPolicy(p *vnl.XfrmPolicy, owned map[int][]*ownedPair) *ownedPair {
	if !ownedPolicyShape(p) {
		return nil
	}
	t := p.Tmpls[0]
	pair := pairOf(owned, t.Reqid, t.Src, t.Dst)
	if pair == nil || !slices.Contains(pair.policies, policyRecordOf(p)) {
		return nil
	}
	return pair
}

// ownedPolicyShape reports whether p has the shape espPolicy builds: an
// allow policy between two hosts for a carrier protocol, in or out, with one
// transport ESP template on the selector's hosts and every other field unset
// (policyFieldsUnset). Shape alone proves nothing about who installed p.
func ownedPolicyShape(p *vnl.XfrmPolicy) bool {
	if p.Action != vnl.XFRM_POLICY_ALLOW || len(p.Tmpls) != 1 || !policyFieldsUnset(p) {
		return false
	}
	if p.Dir != vnl.XFRM_DIR_OUT && p.Dir != vnl.XFRM_DIR_IN {
		return false
	}
	if p.Proto != carrierProto(TunnelTypeGRE) && p.Proto != carrierProto(TunnelTypeIPIP) {
		return false
	}
	t := p.Tmpls[0]
	if t.Proto != vnl.XFRM_PROTO_ESP || t.Mode != vnl.XFRM_MODE_TRANSPORT {
		return false
	}
	if p.Src == nil || p.Dst == nil {
		return false
	}
	return p.Src.String() == hostNet(t.Src).String() && p.Dst.String() == hostNet(t.Dst).String()
}

// policyFieldsUnset reports whether p leaves unset every field espPolicy
// never sets: the selector's interface and ports, the policy's priority,
// mark and xfrm interface id, and its template's SPI and optional flag. The
// kernel-assigned Index is not a field the installer chooses, so it is not
// compared.
func policyFieldsUnset(p *vnl.XfrmPolicy) bool {
	if p.Ifindex != 0 || p.SrcPort != 0 || p.DstPort != 0 {
		return false
	}
	if p.Priority != 0 || p.Mark != nil || p.Ifid != 0 {
		return false
	}
	for _, t := range p.Tmpls {
		if t.Spi != 0 || t.Optional != 0 {
			return false
		}
	}
	return true
}

// namedIPsecLocked returns the SAs and policies the managed IPsec tunnels
// name, but for the tunnel except that is being removed ("" for none). The
// caller holds m.mu.
func (m *Manager) namedIPsecLocked(except string) (map[saKey]bool, map[policyKey]bool) {
	sas := make(map[saKey]bool)
	policies := make(map[policyKey]bool)
	for name, managed := range m.tunnels {
		if name == except || managed.config.effectiveTransport() != TransportIPsec {
			continue
		}
		out, in := ipsecStates(managed.config, nil, nil)
		sas[keyOfSA(out)] = true
		sas[keyOfSA(in)] = true
		polOut, polIn := ipsecPolicies(managed.config)
		policies[keyOfPolicy(polOut)] = true
		policies[keyOfPolicy(polIn)] = true
	}
	return sas, policies
}

// zeroizeStates wipes the key material a state dump carried, this
// manager's and every other installer's alike.
func zeroizeStates(states []vnl.XfrmState) {
	for i := range states {
		for _, algo := range []*vnl.XfrmStateAlgo{states[i].Aead, states[i].Crypt, states[i].Auth} {
			if algo != nil {
				zeroize(algo.Key)
			}
		}
	}
}

// xfrmUnsupported reports whether err says the kernel has no XFRM netlink
// family, in which case no XFRM state can have been installed through it.
func xfrmUnsupported(err error) bool {
	return errors.Is(err, syscall.EPROTONOSUPPORT)
}

// SweepIPsec removes the ESP SAs and policies this manager installed under
// SPIs or endpoints no managed tunnel names any more: what a predecessor
// killed before a configuration change, or a tunnel dropped from the
// configuration while no manager ran, left in the kernel. Call it once the
// configured tunnels are ensured; whatever they name is kept, so live SAs
// keep their sequence numbers. The recorded carrier of a retired pair (a
// tunnel dropped, or replaced under other SPIs) a killed predecessor left up
// goes first, as in removeTunnelLocked, so it never
// sends in the clear once its policies are gone; if it cannot be removed
// the sweep fails with its protection intact. Policies go next, the reverse
// of install, so no policy is left selecting traffic into a removed SA, and
// within a pair the anchor goes last. XFRM state another installer owns is never touched
// (see ownedIPsec and ownedPolicy).
func (m *Manager) SweepIPsec() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	recorded, err := m.inventory.load()
	if err != nil {
		return &ErrIPsecSweepFailed{Op: "read inventory", Cause: err}
	}
	if len(recorded) == 0 {
		return nil
	}
	states, err := m.nl.XfrmStateList(vnl.FAMILY_ALL)
	if err != nil {
		if xfrmUnsupported(err) {
			return nil
		}
		return &ErrIPsecSweepFailed{Op: "list SAs", Cause: err}
	}
	defer zeroizeStates(states)
	return m.sweepOwnedLocked(ownedIPsec(states, recorded), "")
}

// sweepOwnedLocked removes, of the owned pairs, every carrier, policy and SA
// no managed tunnel but except names, in SweepIPsec's order. The caller holds
// m.mu.
func (m *Manager) sweepOwnedLocked(owned map[int][]*ownedPair, except string) error {
	if len(owned) == 0 {
		return nil
	}
	policies, err := m.nl.XfrmPolicyList(vnl.FAMILY_ALL)
	if err != nil {
		return &ErrIPsecSweepFailed{Op: "list policies", Cause: err}
	}

	namedSAs, namedPolicies := m.namedIPsecLocked(except)
	var stale []*vnl.XfrmPolicy
	sweptPolicies := make(map[*ownedPair][]ipsecPolicyRecord)
	for i := range policies {
		p := &policies[i]
		if namedPolicies[keyOfPolicy(p)] {
			continue
		}
		if pair := ownedPolicy(p, owned); pair != nil {
			stale = append(stale, p)
			sweptPolicies[pair] = append(sweptPolicies[pair], policyRecordOf(p))
		}
	}
	retired, err := m.removeStaleCarriersLocked(owned, except)
	if err != nil {
		return err
	}
	for _, p := range stale {
		if err := m.nl.XfrmPolicyDel(p); err != nil && !xfrmMissing(err) {
			return &ErrIPsecSweepFailed{Op: "remove policy", Cause: err}
		}
		m.logger.Info("stale ipsec policy removed",
			slog.String("src", p.Src.String()), slog.String("dst", p.Dst.String()),
			slog.Int("reqid", p.Tmpls[0].Reqid))
	}
	for _, pairs := range owned {
		for _, pair := range pairs {
			var swept []ipsecSARecord
			for _, s := range pair.members {
				if s == pair.anchor || namedSAs[keyOfSA(s)] {
					continue
				}
				if err := m.sweepState(s, namedSAs); err != nil {
					return err
				}
				swept = append(swept, saRecordOf(s))
			}
			if pair.installed {
				if err := m.sweepState(pair.anchor, namedSAs); err != nil {
					return err
				}
			}
			// A pair a managed tunnel still names keeps its record, less
			// what was swept; a retired pair's record goes with its anchor.
			var update error
			if namedSAs[keyOfSA(pair.anchor)] {
				update = m.inventory.forget(pair.anchor, swept, sweptPolicies[pair], retired[pair])
			} else {
				update = m.inventory.remove(pair.anchor)
			}
			if update != nil {
				return &ErrIPsecSweepFailed{Op: "update inventory", Cause: update}
			}
		}
	}
	return nil
}

// removeStaleCarriersLocked deletes every carrier link the inventory records
// for an owned pair that no managed tunnel is named after and whose
// endpoints are that pair's: the link of a tunnel dropped or replaced while
// no manager ran, which would otherwise keep its addresses and routes and
// send in the clear once its protection is gone. It does so whether or not a
// managed tunnel still names the pair: a tunnel of another name may reuse the
// pair's endpoints and SPIs, under another carrier protocol, so the pair's
// SAs stay while the old carrier's policies are stale. Which carriers go
// follows from the recorded ownership alone, not from a stale policy: a
// replacement on the same endpoints and carrier protocol updates the old
// policies in place, so none is stale, yet the old carrier would be left up
// and untracked. A link the inventory does not name is never touched,
// however its endpoints match: matching endpoints do not prove who installed
// it. A managed tunnel's link is never touched either. It returns, per pair,
// the recorded carriers no managed tunnel is named after, which the record
// no longer needs: each was removed, is gone, or is no longer the pair's
// link. The tunnel except, being removed, counts as unmanaged. The caller
// holds m.mu.
func (m *Manager) removeStaleCarriersLocked(owned map[int][]*ownedPair, except string) (map[*ownedPair][]string, error) {
	retired := make(map[*ownedPair][]string)
	for _, pairs := range owned {
		for _, pair := range pairs {
			for _, name := range pair.carriers {
				if _, managed := m.tunnels[name]; !managed || name == except {
					retired[pair] = append(retired[pair], name)
				}
			}
		}
	}
	if len(retired) == 0 {
		return retired, nil
	}
	links, err := m.nl.LinkList()
	if err != nil {
		return nil, &ErrIPsecSweepFailed{Op: "list links", Cause: err}
	}
	for _, link := range links {
		name := link.Attrs().Name
		if !carrierOfPair(link, retiredAnchors(retired, name)) {
			continue
		}
		if err := m.nl.LinkDel(link); err != nil {
			return nil, &ErrIPsecSweepFailed{Op: "remove carrier", Cause: err}
		}
		m.logger.Info("stale ipsec carrier removed", slog.String("name", name))
	}
	return retired, nil
}

// retiredAnchors is the anchors of the pairs that retire the carrier name.
func retiredAnchors(retired map[*ownedPair][]string, name string) []*vnl.XfrmState {
	var anchors []*vnl.XfrmState
	for pair, names := range retired {
		if slices.Contains(names, name) {
			anchors = append(anchors, pair.anchor)
		}
	}
	return anchors
}

// carrierOfPair reports whether link is a GRE or IPIP carrier between the
// endpoints of one of the anchors, in either direction.
func carrierOfPair(link vnl.Link, anchors []*vnl.XfrmState) bool {
	var local, remote net.IP
	switch carrier := link.(type) {
	case *vnl.Gretun:
		local, remote = carrier.Local, carrier.Remote
	case *vnl.Ip6tnl:
		if carrier.Proto != syscall.IPPROTO_GRE {
			return false
		}
		local, remote = carrier.Local, carrier.Remote
	case *vnl.Iptun:
		local, remote = carrier.Local, carrier.Remote
	default:
		return false
	}
	for _, anchor := range anchors {
		if pairEndpoints(local, remote, anchor) {
			return true
		}
	}
	return false
}

// sweepState removes s unless a managed tunnel names it.
func (m *Manager) sweepState(s *vnl.XfrmState, named map[saKey]bool) error {
	if named[keyOfSA(s)] {
		return nil
	}
	if err := m.nl.XfrmStateDel(s); err != nil && !xfrmMissing(err) {
		return &ErrIPsecSweepFailed{Op: "remove SA", Cause: err}
	}
	m.logger.Info("stale ipsec SA removed",
		slog.String("dst", s.Dst.String()), slog.Int("spi", s.Spi), slog.Int("reqid", s.Reqid))
	return nil
}

// rekeyIPsec fetches fresh material and updates both SAs in place
// (XFRM_MSG_UPDSA), outbound first. The SPIs and policies are untouched, so
// traffic keeps flowing through the same selectors; the peer rotates the
// same references in lockstep.
func (m *Manager) rekeyIPsec(ctx context.Context, config TunnelConfig) error {
	outKey, err := fetchKey(ctx, m.keys, config.Name, config.IPsec.KeyRef, espGCMKeyLen)
	if err != nil {
		return &ErrRekeyFailed{Name: config.Name, Cause: err}
	}
	defer zeroize(outKey)
	inKey, err := fetchKey(ctx, m.keys, config.Name, config.IPsec.effectivePeerKeyRef(), espGCMKeyLen)
	if err != nil {
		return &ErrRekeyFailed{Name: config.Name, Cause: err}
	}
	defer zeroize(inKey)

	out, in := ipsecStates(config, outKey, inKey)
	if err := m.nl.XfrmStateUpdate(out); err != nil {
		return &ErrRekeyFailed{Name: config.Name, Cause: err}
	}
	if err := m.nl.XfrmStateUpdate(in); err != nil {
		return &ErrRekeyFailed{Name: config.Name, Cause: err}
	}
	return nil
}
