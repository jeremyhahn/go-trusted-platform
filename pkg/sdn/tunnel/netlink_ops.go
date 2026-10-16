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
	vnl "github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// netlinkOps abstracts netlink operations for testability.
// Unit tests provide a mock implementation to avoid requiring root/CAP_NET_ADMIN.
type netlinkOps interface {
	LinkAdd(link vnl.Link) error
	LinkDel(link vnl.Link) error
	LinkSetUp(link vnl.Link) error
	LinkSetMTU(link vnl.Link, mtu int) error
	LinkByName(name string) (vnl.Link, error)
	AddrAdd(link vnl.Link, addr *vnl.Addr) error
	AddrList(link vnl.Link, family int) ([]vnl.Addr, error)
	LinkList() ([]vnl.Link, error)

	// IPsec (XFRM) state and policy.
	XfrmStateAdd(state *vnl.XfrmState) error
	XfrmStateUpdate(state *vnl.XfrmState) error
	XfrmStateDel(state *vnl.XfrmState) error
	XfrmStateGet(state *vnl.XfrmState) (*vnl.XfrmState, error)
	XfrmPolicyUpdate(policy *vnl.XfrmPolicy) error
	XfrmPolicyDel(policy *vnl.XfrmPolicy) error
	XfrmPolicyGet(policy *vnl.XfrmPolicy) (*vnl.XfrmPolicy, error)

	// Policy routing: rules and per-table routes.
	RuleAdd(rule *vnl.Rule) error
	RuleDel(rule *vnl.Rule) error
	RuleList(family int) ([]vnl.Rule, error)
	RouteReplace(route *vnl.Route) error
	RouteDel(route *vnl.Route) error
	RouteListFiltered(family int, filter *vnl.Route, mask uint64) ([]vnl.Route, error)
}

// realNetlinkOps calls the real vishvananda/netlink functions.
type realNetlinkOps struct{}

func (r *realNetlinkOps) LinkAdd(link vnl.Link) error {
	return vnl.LinkAdd(link)
}

func (r *realNetlinkOps) LinkDel(link vnl.Link) error {
	return vnl.LinkDel(link)
}

func (r *realNetlinkOps) LinkSetUp(link vnl.Link) error {
	return vnl.LinkSetUp(link)
}

func (r *realNetlinkOps) LinkSetMTU(link vnl.Link, mtu int) error {
	return vnl.LinkSetMTU(link, mtu)
}

func (r *realNetlinkOps) LinkByName(name string) (vnl.Link, error) {
	return vnl.LinkByName(name)
}

func (r *realNetlinkOps) AddrAdd(link vnl.Link, addr *vnl.Addr) error {
	return vnl.AddrAdd(link, addr)
}

func (r *realNetlinkOps) AddrList(link vnl.Link, family int) ([]vnl.Addr, error) {
	return vnl.AddrList(link, family)
}

func (r *realNetlinkOps) LinkList() ([]vnl.Link, error) {
	return vnl.LinkList()
}

func (r *realNetlinkOps) XfrmStateAdd(state *vnl.XfrmState) error {
	return vnl.XfrmStateAdd(state)
}

func (r *realNetlinkOps) XfrmStateUpdate(state *vnl.XfrmState) error {
	return vnl.XfrmStateUpdate(state)
}

func (r *realNetlinkOps) XfrmStateDel(state *vnl.XfrmState) error {
	return vnl.XfrmStateDel(state)
}

// XfrmStateGet reads one SA back. The library parses neither the ESN flag
// nor the ESN replay window (it zeroes the legacy window when it installs
// an ESN SA), so both are read from the raw reply on top.
func (r *realNetlinkOps) XfrmStateGet(state *vnl.XfrmState) (*vnl.XfrmState, error) {
	have, err := vnl.XfrmStateGet(state)
	if err != nil {
		return nil, err
	}
	esn, window, err := xfrmReplayESN(state)
	if err != nil {
		if have.Aead != nil {
			zeroize(have.Aead.Key)
		}
		return nil, err
	}
	have.ESN = esn
	if esn {
		have.ReplayWindow = window
	}
	return have, nil
}

// xfrmReplayESN asks the kernel for one SA (XFRM_MSG_GETSA) and returns
// whether it uses extended sequence numbers and, if so, its replay window
// from struct xfrm_replay_state_esn (the sixth u32).
func xfrmReplayESN(state *vnl.XfrmState) (bool, int, error) {
	req := nl.NewNetlinkRequest(nl.XFRM_MSG_GETSA, unix.NLM_F_ACK)
	id := &nl.XfrmUsersaId{}
	id.Family = uint16(nl.GetIPFamily(state.Dst))
	id.Daddr.FromIP(state.Dst)
	id.Proto = uint8(state.Proto)
	id.Spi = nl.Swap32(uint32(state.Spi))
	req.AddData(id)
	req.AddData(nl.NewRtAttr(nl.XFRMA_SRCADDR, state.Src.To16()))
	msgs, err := req.Execute(unix.NETLINK_XFRM, nl.XFRM_MSG_NEWSA)
	if err != nil {
		return false, 0, err
	}
	// The reply carries the SA's keys: wipe every message once parsed.
	defer func() {
		for _, msg := range msgs {
			zeroize(msg)
		}
	}()
	if len(msgs) == 0 {
		return false, 0, &ErrXfrmReply{Spi: state.Spi, Reason: "empty reply"}
	}
	return parseReplayESN(state.Spi, msgs[0])
}

// parseReplayESN decodes an XFRM_MSG_NEWSA reply (struct xfrm_usersa_info
// and its attributes) into whether the SA uses extended sequence numbers and
// its replay window: the ESN replay state's window for an ESN SA, the legacy
// one otherwise.
func parseReplayESN(spi int, msg []byte) (bool, int, error) {
	if len(msg) < nl.SizeofXfrmUsersaInfo {
		return false, 0, &ErrXfrmReply{Spi: spi, Reason: "short reply"}
	}
	info := nl.DeserializeXfrmUsersaInfo(msg)
	if info.Flags&nl.XFRM_STATE_ESN == 0 {
		return false, int(info.ReplayWindow), nil
	}
	attrs, err := nl.ParseRouteAttr(msg[nl.SizeofXfrmUsersaInfo:])
	if err != nil {
		return false, 0, &ErrXfrmReply{Spi: spi, Reason: "unparsable attributes", Cause: err}
	}
	for _, attr := range attrs {
		if attr.Attr.Type == nl.XFRMA_REPLAY_ESN_VAL && len(attr.Value) >= replayESNWindowEnd {
			return true, int(nl.NativeEndian().Uint32(attr.Value[replayESNWindowEnd-4 : replayESNWindowEnd])), nil
		}
	}
	return false, 0, &ErrXfrmReply{Spi: spi, Reason: "ESN SA without its replay state"}
}

// replayESNWindowEnd is where replay_window ends in struct
// xfrm_replay_state_esn: bmp_len, oseq, seq, oseq_hi, seq_hi, replay_window,
// each a u32.
const replayESNWindowEnd = 24

func (r *realNetlinkOps) XfrmPolicyUpdate(policy *vnl.XfrmPolicy) error {
	return vnl.XfrmPolicyUpdate(policy)
}

func (r *realNetlinkOps) XfrmPolicyDel(policy *vnl.XfrmPolicy) error {
	return vnl.XfrmPolicyDel(policy)
}

func (r *realNetlinkOps) XfrmPolicyGet(policy *vnl.XfrmPolicy) (*vnl.XfrmPolicy, error) {
	return vnl.XfrmPolicyGet(policy)
}

func (r *realNetlinkOps) RuleAdd(rule *vnl.Rule) error {
	return vnl.RuleAdd(rule)
}

func (r *realNetlinkOps) RuleDel(rule *vnl.Rule) error {
	return vnl.RuleDel(rule)
}

func (r *realNetlinkOps) RuleList(family int) ([]vnl.Rule, error) {
	return vnl.RuleList(family)
}

func (r *realNetlinkOps) RouteReplace(route *vnl.Route) error {
	return vnl.RouteReplace(route)
}

func (r *realNetlinkOps) RouteDel(route *vnl.Route) error {
	return vnl.RouteDel(route)
}

func (r *realNetlinkOps) RouteListFiltered(family int, filter *vnl.Route, mask uint64) ([]vnl.Route, error) {
	return vnl.RouteListFiltered(family, filter, mask)
}
