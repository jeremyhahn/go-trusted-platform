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
	"net"
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
	for _, want := range []*vnl.XfrmState{out, in} {
		if err := m.reconcileState(want); err != nil {
			return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
		}
	}
	polOut, polIn := ipsecPolicies(config)
	for _, want := range []*vnl.XfrmPolicy{polOut, polIn} {
		if err := m.reconcilePolicy(want); err != nil {
			return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
		}
	}
	return nil
}

// reconcileState keeps an installed SA that matches want, replaces one that
// differs and adds a missing one. A differing SA is deleted and added, so
// its key and algorithm are replaced whole.
func (m *Manager) reconcileState(want *vnl.XfrmState) error {
	have, err := m.nl.XfrmStateGet(want)
	if err != nil && !xfrmMissing(err) {
		return err
	}
	if err == nil {
		matches := espStateMatches(have, want)
		if have.Aead != nil {
			zeroize(have.Aead.Key)
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

// reconcilePolicy keeps an installed policy that matches want and otherwise
// installs want; XFRM_MSG_UPDPOLICY adds a missing policy and replaces a
// differing one in place, with no window in which the selector is open.
func (m *Manager) reconcilePolicy(want *vnl.XfrmPolicy) error {
	have, err := m.nl.XfrmPolicyGet(want)
	if err != nil && !xfrmMissing(err) {
		return err
	}
	if err == nil && espPolicyMatches(have, want) {
		return nil
	}
	return m.nl.XfrmPolicyUpdate(want)
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
// selector and direction allows the traffic through want's one template.
func espPolicyMatches(have, want *vnl.XfrmPolicy) bool {
	if have.Action != want.Action || have.Mark != nil || len(have.Tmpls) != 1 {
		return false
	}
	h, w := have.Tmpls[0], want.Tmpls[0]
	// Optional is compared because an optional template lets unencrypted
	// carrier traffic through: adopting it would keep weaker protection.
	return h.Src.Equal(w.Src) && h.Dst.Equal(w.Dst) && h.Proto == w.Proto && h.Mode == w.Mode &&
		h.Reqid == w.Reqid && h.Optional == w.Optional
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
		return false, err
	}
	return true, nil
}

// removeIPsecStates deletes both SAs; errors are ignored because the
// states may already be gone and removal must make progress.
func (m *Manager) removeIPsecStates(config TunnelConfig) {
	out, in := ipsecStates(config, nil, nil)
	_ = m.nl.XfrmStateDel(out)
	_ = m.nl.XfrmStateDel(in)
}

// removeIPsec takes the policies out before the SAs, the reverse of install.
func (m *Manager) removeIPsec(config TunnelConfig) error {
	polOut, polIn := ipsecPolicies(config)
	var firstErr error
	if err := m.nl.XfrmPolicyDel(polOut); err != nil {
		firstErr = err
	}
	if err := m.nl.XfrmPolicyDel(polIn); err != nil && firstErr == nil {
		firstErr = err
	}
	m.removeIPsecStates(config)
	if firstErr != nil {
		return &ErrTunnelRemoveFailed{Name: config.Name, Cause: firstErr}
	}
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
