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
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vnl "github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func ipsecConfig() TunnelConfig {
	return TunnelConfig{
		Name: "gre-pri", Type: TunnelTypeGRE, Transport: TransportIPsec,
		Local: "198.51.100.36", Remote: "198.51.100.100", TunnelIP: "10.255.0.1/30",
		IPsec: &IPsecConfig{KeyRef: "kms://platform/tunnel/pop-a/out", PeerKeyRef: "kms://platform/tunnel/pop-a/in", SPIOut: 0x1001, SPIIn: 0x1002},
	}
}

func keysFor(cfg TunnelConfig) *mockKeys {
	return &mockKeys{keys: map[string][]byte{
		cfg.IPsec.KeyRef:                espKey(0xAA),
		cfg.IPsec.effectivePeerKeyRef(): espKey(0xBB),
	}}
}

func TestIPsecConfig_Validate(t *testing.T) {
	cases := map[string]struct {
		mutate func(*TunnelConfig)
		reason string
	}{
		"missing section":   {func(c *TunnelConfig) { c.IPsec = nil }, "requires an ipsec section"},
		"missing key ref":   {func(c *TunnelConfig) { c.IPsec.KeyRef = "" }, "key-ref is required"},
		"zero spi":          {func(c *TunnelConfig) { c.IPsec.SPIIn = 0 }, "non-zero"},
		"equal spis":        {func(c *TunnelConfig) { c.IPsec.SPIIn = c.IPsec.SPIOut }, "must differ"},
		"negative replay":   {func(c *TunnelConfig) { c.IPsec.ReplayWindow = -1 }, "replay-window"},
		"negative rekey":    {func(c *TunnelConfig) { c.IPsec.RekeyInterval = -1 }, "rekey-interval"},
		"wireguard section": {func(c *TunnelConfig) { c.WireGuard = &WireGuardConfig{} }, "no wireguard section"},
		"unknown transport": {func(c *TunnelConfig) { c.Transport = "carrier-pigeon" }, "transport must be"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := ipsecConfig()
			c.mutate(&cfg)
			err := cfg.Validate()
			var invalid *ErrInvalidTunnelConfig
			require.True(t, errors.As(err, &invalid), "got %v", err)
			assert.Contains(t, err.Error(), c.reason)
		})
	}
	valid := ipsecConfig()
	require.NoError(t, valid.Validate())
	assert.Equal(t, DefaultReplayWindow, valid.IPsec.effectiveReplayWindow())
	assert.Equal(t, DefaultRekeyInterval, valid.IPsec.EffectiveRekeyInterval())
	assert.Equal(t, "kms://platform/tunnel/pop-a/in", valid.IPsec.effectivePeerKeyRef())
	valid.IPsec.PeerKeyRef = ""
	assert.Equal(t, valid.IPsec.KeyRef, valid.IPsec.effectivePeerKeyRef())

	gre := ipsecConfig()
	gre.Transport = ""
	err := gre.Validate()
	require.Error(t, err, "a gre transport must not carry an ipsec section")
	assert.Contains(t, err.Error(), "takes no ipsec")
}

func TestIPsecStatesAndPolicies(t *testing.T) {
	cfg := ipsecConfig()
	out, in := ipsecStates(cfg, espKey(1), espKey(2))
	assert.Equal(t, "198.51.100.36", out.Src.String())
	assert.Equal(t, "198.51.100.100", out.Dst.String())
	assert.Equal(t, 0x1001, out.Spi)
	assert.Equal(t, 0x1002, in.Spi)
	assert.Equal(t, out.Reqid, in.Reqid)
	assert.Equal(t, vnl.XFRM_PROTO_ESP, out.Proto)
	assert.Equal(t, vnl.XFRM_MODE_TRANSPORT, out.Mode)
	assert.Equal(t, espGCMAlgo, out.Aead.Name)
	assert.Equal(t, espGCMICVBits, out.Aead.ICVLen)
	assert.Equal(t, DefaultReplayWindow, out.ReplayWindow)
	assert.True(t, out.ESN)
	assert.Nil(t, out.Auth, "AEAD carries integrity; no separate auth algorithm")
	assert.Nil(t, out.Crypt)

	polOut, polIn := ipsecPolicies(cfg)
	assert.Equal(t, vnl.XFRM_DIR_OUT, polOut.Dir)
	assert.Equal(t, vnl.XFRM_DIR_IN, polIn.Dir)
	assert.Equal(t, "198.51.100.36/32", polOut.Src.String())
	assert.Equal(t, "198.51.100.100/32", polOut.Dst.String())
	assert.Equal(t, vnl.Proto(47), polOut.Proto, "only the GRE carrier is selected")
	assert.Equal(t, vnl.XFRM_POLICY_ALLOW, polOut.Action)
	require.Len(t, polOut.Tmpls, 1)
	assert.Equal(t, out.Reqid, polOut.Tmpls[0].Reqid)

	cfg.Type = TunnelTypeIPIP
	polOut, _ = ipsecPolicies(cfg)
	assert.Equal(t, vnl.Proto(4), polOut.Proto)
}

func TestManager_EnsureTunnel_IPsec(t *testing.T) {
	mock := newMockNetlinkOps()
	cfg := ipsecConfig()
	keys := keysFor(cfg)
	m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keys))

	require.NoError(t, m.EnsureTunnel(context.Background(), cfg))

	require.Len(t, mock.xfrmStates, 2, "two SAs")
	require.Len(t, mock.xfrmPolicies, 2, "two policies")
	assert.Equal(t, espKey(0xAA), mock.xfrmStates[0].Aead.Key)
	assert.Equal(t, espKey(0xBB), mock.xfrmStates[1].Aead.Key)
	_, hasLink := mock.links[cfg.Name]
	assert.True(t, hasLink, "the GRE carrier exists")
	assert.Equal(t, 2, keys.calls)

	// Idempotent: nothing is re-fetched or re-programmed.
	require.NoError(t, m.EnsureTunnel(context.Background(), cfg))
	assert.Equal(t, 2, keys.calls)
	assert.Len(t, mock.xfrmStates, 2)

	require.NoError(t, m.RemoveTunnel(context.Background(), cfg.Name))
	assert.Empty(t, mock.xfrmStates, "SAs removed with the tunnel")
	assert.Empty(t, mock.xfrmPolicies, "policies removed with the tunnel")
	_, hasLink = mock.links[cfg.Name]
	assert.False(t, hasLink)
}

func TestManager_EnsureTunnel_IPsecZeroizesTheCallersKey(t *testing.T) {
	mock := newMockNetlinkOps()
	cfg := ipsecConfig()
	var seen []byte
	mock.xfrmStateAddFn = func(s *vnl.XfrmState) error {
		if seen == nil {
			seen = s.Aead.Key // the caller's slice, not a copy
		}
		return nil
	}
	m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)))
	require.NoError(t, m.EnsureTunnel(context.Background(), cfg))
	require.NotNil(t, seen)
	assert.Equal(t, make([]byte, espGCMKeyLen), seen, "key material is zeroized after the kernel holds it")
}

func TestManager_EnsureTunnel_IPsecRequiresKeyProvider(t *testing.T) {
	m := newManagerWithOps(testLogger(), newMockNetlinkOps())
	err := m.EnsureTunnel(context.Background(), ipsecConfig())
	var want *ErrKeyProviderRequired
	require.True(t, errors.As(err, &want), "got %v", err)
	assert.Equal(t, TransportIPsec, want.Transport)
}

func TestManager_EnsureTunnel_IPsecKeyFailures(t *testing.T) {
	cfg := ipsecConfig()
	t.Run("resolver error", func(t *testing.T) {
		mock := newMockNetlinkOps()
		m := newManagerWithOps(testLogger(), mock, WithKeyProvider(&mockKeys{err: errors.New("kms down")}))
		err := m.EnsureTunnel(context.Background(), cfg)
		var km *ErrKeyMaterial
		require.True(t, errors.As(err, &km), "got %v", err)
		assert.Contains(t, err.Error(), cfg.IPsec.KeyRef)
		assert.Empty(t, mock.xfrmStates, "nothing programmed")
	})
	t.Run("wrong length", func(t *testing.T) {
		mock := newMockNetlinkOps()
		m := newManagerWithOps(testLogger(), mock, WithKeyProvider(&mockKeys{keys: map[string][]byte{cfg.IPsec.KeyRef: []byte("short"), cfg.IPsec.PeerKeyRef: espKey(1)}}))
		err := m.EnsureTunnel(context.Background(), cfg)
		var km *ErrKeyMaterial
		require.True(t, errors.As(err, &km), "got %v", err)
		assert.Contains(t, err.Error(), "36 bytes")
		assert.NotContains(t, err.Error(), "short", "material never appears in an error")
		assert.Empty(t, mock.xfrmStates)
	})
	t.Run("empty", func(t *testing.T) {
		mock := newMockNetlinkOps()
		m := newManagerWithOps(testLogger(), mock, WithKeyProvider(&mockKeys{keys: map[string][]byte{cfg.IPsec.KeyRef: {}, cfg.IPsec.PeerKeyRef: espKey(1)}}))
		err := m.EnsureTunnel(context.Background(), cfg)
		var km *ErrKeyMaterial
		require.True(t, errors.As(err, &km), "got %v", err)
	})
}

func TestManager_EnsureTunnel_IPsecRollsBackOnFailure(t *testing.T) {
	cfg := ipsecConfig()
	t.Run("second SA fails", func(t *testing.T) {
		mock := newMockNetlinkOps()
		n := 0
		mock.xfrmStateAddFn = func(s *vnl.XfrmState) error {
			n++
			if n == 2 {
				return errors.New("ENOMEM")
			}
			return mock.recordState(s)
		}
		m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)))
		err := m.EnsureTunnel(context.Background(), cfg)
		var cf *ErrTunnelCreateFailed
		require.True(t, errors.As(err, &cf), "got %v", err)
		assert.Empty(t, mock.xfrmStates, "the first SA is removed again")
		assert.Empty(t, mock.xfrmPolicies)
	})
	t.Run("policy fails", func(t *testing.T) {
		mock := newMockNetlinkOps()
		mock.xfrmPolicyUpdateFn = func(*vnl.XfrmPolicy) error { return errors.New("EPERM") }
		m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)))
		err := m.EnsureTunnel(context.Background(), cfg)
		require.Error(t, err)
		assert.Empty(t, mock.xfrmStates, "SAs never outlive a failed policy")
		_, hasLink := mock.links[cfg.Name]
		assert.False(t, hasLink, "the carrier is never created without protection")
	})
	t.Run("SA read fails", func(t *testing.T) {
		mock := newMockNetlinkOps()
		mock.xfrmStateGetFn = func(*vnl.XfrmState) (*vnl.XfrmState, error) { return nil, syscall.EPERM }
		m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)))
		err := m.EnsureTunnel(context.Background(), cfg)
		var cf *ErrTunnelCreateFailed
		require.ErrorAs(t, err, &cf)
		assert.ErrorIs(t, err, syscall.EPERM)
		assert.Empty(t, mock.xfrmStates, "nothing is programmed over an SA that cannot be read")
		_, hasLink := mock.links[cfg.Name]
		assert.False(t, hasLink)
	})
	t.Run("carrier fails after protection", func(t *testing.T) {
		mock := newMockNetlinkOps()
		mock.linkAddFn = func(vnl.Link) error { return errors.New("EEXIST") }
		m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)))
		require.Error(t, m.EnsureTunnel(context.Background(), cfg))
		assert.Empty(t, mock.xfrmStates, "protection is removed when the carrier cannot be created")
		assert.Empty(t, mock.xfrmPolicies)
	})
}

// leftIPsec installs cfg and returns the kernel as a killed datapath leaves
// it: the carrier, both SAs and both policies still in place.
func leftIPsec(t *testing.T, cfg TunnelConfig) *mockNetlinkOps {
	t.Helper()
	mock := newMockNetlinkOps()
	killed := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)))
	require.NoError(t, killed.EnsureTunnel(context.Background(), cfg))
	return mock
}

// stateBySPI is the SA the mock holds for spi, or nil.
func stateBySPI(mock *mockNetlinkOps, spi uint32) *vnl.XfrmState {
	for _, state := range mock.xfrmStates {
		if state.Spi == int(spi) {
			return state
		}
	}
	return nil
}

func TestManager_EnsureTunnel_IPsecRelaunchKeepsLiveSAs(t *testing.T) {
	cfg := ipsecConfig()
	mock := leftIPsec(t, cfg)
	carrier := mock.links[cfg.Name]
	out, in := stateBySPI(mock, cfg.IPsec.SPIOut), stateBySPI(mock, cfg.IPsec.SPIIn)
	rewrites := mock.xfrmPolicyUpdates
	mock.linkAddFn = func(vnl.Link) error { return errors.New("an adopted carrier is never recreated") }
	mock.linkDelFn = func(vnl.Link) error { return errors.New("an adopted carrier is never deleted") }
	mock.xfrmStateAddFn = func(*vnl.XfrmState) error { return errors.New("a live SA is never re-added") }
	mock.xfrmStateDelFn = func(*vnl.XfrmState) error { return errors.New("a live SA is never deleted") }
	relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)))

	require.NoError(t, relaunched.EnsureTunnel(context.Background(), cfg))

	assert.Same(t, carrier, mock.links[cfg.Name], "the carrier is adopted")
	assert.Same(t, out, stateBySPI(mock, cfg.IPsec.SPIOut), "the outbound SA keeps its sequence numbers")
	assert.Same(t, in, stateBySPI(mock, cfg.IPsec.SPIIn), "the inbound SA keeps its replay state")
	assert.Equal(t, rewrites, mock.xfrmPolicyUpdates, "matching policies are not rewritten")
	assert.Contains(t, relaunched.tunnels, cfg.Name, "the adopted tunnel is managed from now on")
}

func TestManager_EnsureTunnel_IPsecRelaunchRepairsWhatDiffers(t *testing.T) {
	cfg := ipsecConfig()
	cases := map[string]struct {
		mutate      func(*mockNetlinkOps)
		outKey      byte
		outReplaced bool
		inReplaced  bool
		rewrites    int
		carrierKept bool
	}{
		"rotated outbound key": {
			outKey: 0xCC, outReplaced: true, carrierKept: true,
		},
		"key zeroed by lockdown": {
			mutate:      func(m *mockNetlinkOps) { clear(m.xfrmStates[0].Aead.Key) },
			outReplaced: true, carrierKept: true,
		},
		"other replay window": {
			mutate:     func(m *mockNetlinkOps) { m.xfrmStates[1].ReplayWindow = 7 },
			inReplaced: true, carrierKept: true,
		},
		"inbound SA missing": {
			mutate:     func(m *mockNetlinkOps) { m.xfrmStates = m.xfrmStates[:1] },
			inReplaced: true, carrierKept: true,
		},
		"policy with another request id": {
			mutate: func(m *mockNetlinkOps) {
				stale := *m.xfrmPolicies[0]
				stale.Tmpls = []vnl.XfrmPolicyTmpl{stale.Tmpls[0]}
				stale.Tmpls[0].Reqid = 99
				m.xfrmPolicies[0] = &stale
			},
			rewrites: 1, carrierKept: true,
		},
		"inbound policy with optional template": {
			mutate: func(m *mockNetlinkOps) {
				weak := *m.xfrmPolicies[1]
				weak.Tmpls = []vnl.XfrmPolicyTmpl{weak.Tmpls[0]}
				weak.Tmpls[0].Optional = 1
				m.xfrmPolicies[1] = &weak
			},
			rewrites: 1, carrierKept: true,
		},
		"inbound policy missing": {
			mutate:   func(m *mockNetlinkOps) { m.xfrmPolicies = m.xfrmPolicies[:1] },
			rewrites: 1, carrierKept: true,
		},
		"carrier differs": {
			mutate: func(m *mockNetlinkOps) { m.links[cfg.Name].Attrs().MTU = 1500 },
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			mock := leftIPsec(t, cfg)
			carrier := mock.links[cfg.Name]
			out, in := stateBySPI(mock, cfg.IPsec.SPIOut), stateBySPI(mock, cfg.IPsec.SPIIn)
			rewrites := mock.xfrmPolicyUpdates
			if c.mutate != nil {
				c.mutate(mock)
			}
			keys := keysFor(cfg)
			if c.outKey != 0 {
				keys.keys[cfg.IPsec.KeyRef] = espKey(c.outKey)
			}
			relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keys))

			require.NoError(t, relaunched.EnsureTunnel(context.Background(), cfg))

			gotOut, gotIn := stateBySPI(mock, cfg.IPsec.SPIOut), stateBySPI(mock, cfg.IPsec.SPIIn)
			require.NotNil(t, gotOut)
			require.NotNil(t, gotIn)
			require.Len(t, mock.xfrmStates, 2)
			assert.Equal(t, c.outReplaced, out != gotOut, "outbound SA replaced")
			assert.Equal(t, c.inReplaced, in != gotIn, "inbound SA replaced")
			assert.Equal(t, keys.keys[cfg.IPsec.KeyRef], gotOut.Aead.Key)
			assert.Equal(t, espKey(0xBB), gotIn.Aead.Key)
			assert.Equal(t, cfg.IPsec.effectiveReplayWindow(), gotIn.ReplayWindow)

			assert.Equal(t, rewrites+c.rewrites, mock.xfrmPolicyUpdates, "policy rewrites")
			require.Len(t, mock.xfrmPolicies, 2)
			wantOut, wantIn := ipsecPolicies(cfg)
			for _, want := range []*vnl.XfrmPolicy{wantOut, wantIn} {
				have, err := mock.XfrmPolicyGet(want)
				require.NoError(t, err)
				assert.True(t, espPolicyMatches(have, want), "policy %v", want.Dir)
			}

			assert.Equal(t, c.carrierKept, carrier == mock.links[cfg.Name], "carrier kept")
		})
	}
}

func TestManager_EnsureTunnel_IPsecRelaunchFailuresTearNothingDown(t *testing.T) {
	cfg := ipsecConfig()
	cases := map[string]func(*mockNetlinkOps){
		"SA read": func(m *mockNetlinkOps) {
			m.xfrmStateGetFn = func(*vnl.XfrmState) (*vnl.XfrmState, error) { return nil, syscall.EPERM }
		},
		"policy read": func(m *mockNetlinkOps) {
			m.xfrmPolicyGetFn = func(*vnl.XfrmPolicy) (*vnl.XfrmPolicy, error) { return nil, syscall.EPERM }
		},
		"stale SA delete": func(m *mockNetlinkOps) {
			m.xfrmStates[0].ReplayWindow = 7
			m.xfrmStateDelFn = func(*vnl.XfrmState) error { return syscall.EPERM }
		},
		"policy write": func(m *mockNetlinkOps) {
			m.xfrmPolicies = m.xfrmPolicies[:1]
			m.xfrmPolicyUpdateFn = func(*vnl.XfrmPolicy) error { return syscall.EPERM }
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			mock := leftIPsec(t, cfg)
			carrier := mock.links[cfg.Name]
			mutate(mock)
			relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)))

			err := relaunched.EnsureTunnel(context.Background(), cfg)

			var cf *ErrTunnelCreateFailed
			require.ErrorAs(t, err, &cf)
			assert.ErrorIs(t, err, syscall.EPERM)
			assert.NotContains(t, relaunched.tunnels, cfg.Name)
			assert.Same(t, carrier, mock.links[cfg.Name], "the carrier is left for the next attempt")
			assert.Len(t, mock.xfrmStates, 2, "live SAs are left for the next attempt")
		})
	}
}

func TestXfrmMissing(t *testing.T) {
	assert.True(t, xfrmMissing(syscall.ESRCH), "an SA that is not installed")
	assert.True(t, xfrmMissing(fmt.Errorf("get: %w", syscall.ENOENT)), "a policy that is not installed")
	assert.False(t, xfrmMissing(syscall.EPERM))
	assert.False(t, xfrmMissing(nil))
}

func TestEspStateMatches(t *testing.T) {
	local, remote := net.ParseIP("198.51.100.36"), net.ParseIP("198.51.100.100")
	want := espState(local, remote, 0x1001, 0x1001, 32, espKey(0xAA))
	have := func(mutate func(*vnl.XfrmState)) *vnl.XfrmState {
		h := espState(local, remote, 0x1001, 0x1001, 32, espKey(0xAA))
		mutate(h)
		return h
	}
	assert.True(t, espStateMatches(have(func(*vnl.XfrmState) {}), want))

	differs := map[string]func(*vnl.XfrmState){
		"source":        func(s *vnl.XfrmState) { s.Src = net.ParseIP("198.51.100.37") },
		"destination":   func(s *vnl.XfrmState) { s.Dst = net.ParseIP("198.51.100.101") },
		"protocol":      func(s *vnl.XfrmState) { s.Proto = vnl.XFRM_PROTO_AH },
		"spi":           func(s *vnl.XfrmState) { s.Spi = 0x1002 },
		"mode":          func(s *vnl.XfrmState) { s.Mode = vnl.XFRM_MODE_TUNNEL },
		"request id":    func(s *vnl.XfrmState) { s.Reqid = 7 },
		"no ESN":        func(s *vnl.XfrmState) { s.ESN = false },
		"replay window": func(s *vnl.XfrmState) { s.ReplayWindow = 64 },
		"algorithm":     func(s *vnl.XfrmState) { s.Aead.Name = "rfc4309(ccm(aes))" },
		"ICV length":    func(s *vnl.XfrmState) { s.Aead.ICVLen = 64 },
		"key":           func(s *vnl.XfrmState) { s.Aead.Key[0] ^= 1 },
		"zeroed key":    func(s *vnl.XfrmState) { clear(s.Aead.Key) },
		"no AEAD":       func(s *vnl.XfrmState) { s.Aead = nil },
		"encapsulation": func(s *vnl.XfrmState) { s.Encap = &vnl.XfrmStateEncap{} },
		"mark":          func(s *vnl.XfrmState) { s.Mark = &vnl.XfrmMark{Value: 1} },
	}
	for name, mutate := range differs {
		t.Run(name, func(t *testing.T) {
			assert.False(t, espStateMatches(have(mutate), want))
		})
	}
}

func TestEspPolicyMatches(t *testing.T) {
	local, remote := net.ParseIP("198.51.100.36"), net.ParseIP("198.51.100.100")
	want := espPolicy(local, remote, carrierProto(TunnelTypeGRE), vnl.XFRM_DIR_OUT, 0x1001)
	have := func(mutate func(*vnl.XfrmPolicy)) *vnl.XfrmPolicy {
		h := espPolicy(local, remote, carrierProto(TunnelTypeGRE), vnl.XFRM_DIR_OUT, 0x1001)
		mutate(h)
		return h
	}
	assert.True(t, espPolicyMatches(have(func(*vnl.XfrmPolicy) {}), want))

	differs := map[string]func(*vnl.XfrmPolicy){
		"action":            func(p *vnl.XfrmPolicy) { p.Action = vnl.XFRM_POLICY_BLOCK },
		"mark":              func(p *vnl.XfrmPolicy) { p.Mark = &vnl.XfrmMark{Value: 1} },
		"no template":       func(p *vnl.XfrmPolicy) { p.Tmpls = nil },
		"two templates":     func(p *vnl.XfrmPolicy) { p.Tmpls = append(p.Tmpls, p.Tmpls[0]) },
		"template source":   func(p *vnl.XfrmPolicy) { p.Tmpls[0].Src = net.ParseIP("198.51.100.37") },
		"template dest":     func(p *vnl.XfrmPolicy) { p.Tmpls[0].Dst = net.ParseIP("198.51.100.101") },
		"template proto":    func(p *vnl.XfrmPolicy) { p.Tmpls[0].Proto = vnl.XFRM_PROTO_AH },
		"template mode":     func(p *vnl.XfrmPolicy) { p.Tmpls[0].Mode = vnl.XFRM_MODE_TUNNEL },
		"template request":  func(p *vnl.XfrmPolicy) { p.Tmpls[0].Reqid = 7 },
		"optional template": func(p *vnl.XfrmPolicy) { p.Tmpls[0].Optional = 1 },
	}
	for name, mutate := range differs {
		t.Run(name, func(t *testing.T) {
			assert.False(t, espPolicyMatches(have(mutate), want))
		})
	}
}

// saReply is an XFRM_MSG_NEWSA payload: struct xfrm_usersa_info with the
// given flags and legacy replay window, then attrs.
func saReply(flags, window uint8, attrs ...[]byte) []byte {
	msg := (&nl.XfrmUsersaInfo{Flags: flags, ReplayWindow: window}).Serialize()
	for _, attr := range attrs {
		msg = append(msg, attr...)
	}
	return msg
}

func TestParseReplayESN(t *testing.T) {
	replayState := (&nl.XfrmReplayStateEsn{BmpLen: 4, OSeq: 9, ReplayWindow: 128, Bmp: make([]uint32, 4)}).Serialize()

	t.Run("ESN window from the replay state", func(t *testing.T) {
		esn, window, err := parseReplayESN(0x1001, saReply(nl.XFRM_STATE_ESN, 0,
			nl.NewRtAttr(nl.XFRMA_REPLAY_ESN_VAL, replayState).Serialize()))
		require.NoError(t, err)
		assert.True(t, esn)
		assert.Equal(t, 128, window)
	})
	t.Run("legacy window without ESN", func(t *testing.T) {
		esn, window, err := parseReplayESN(0x1001, saReply(0, 32))
		require.NoError(t, err)
		assert.False(t, esn)
		assert.Equal(t, 32, window)
	})

	failures := map[string][]byte{
		"short reply":                     make([]byte, nl.SizeofXfrmUsersaInfo-1),
		"ESN SA without its replay state": saReply(nl.XFRM_STATE_ESN, 0),
		"truncated replay state": saReply(nl.XFRM_STATE_ESN, 0,
			nl.NewRtAttr(nl.XFRMA_REPLAY_ESN_VAL, replayState[:replayESNWindowEnd-1]).Serialize()),
		"unparsable attributes": saReply(nl.XFRM_STATE_ESN, 0, []byte{0xff, 0x00, 0x01, 0x00}),
	}
	for name, msg := range failures {
		t.Run(name, func(t *testing.T) {
			_, _, err := parseReplayESN(0x1001, msg)
			var reply *ErrXfrmReply
			require.ErrorAs(t, err, &reply)
			assert.Equal(t, 0x1001, reply.Spi)
		})
	}
}

func TestManager_Rekey(t *testing.T) {
	mock := newMockNetlinkOps()
	cfg := ipsecConfig()
	keys := keysFor(cfg)
	m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keys))
	require.NoError(t, m.EnsureTunnel(context.Background(), cfg))

	keys.keys[cfg.IPsec.KeyRef] = espKey(0xCC)
	keys.keys[cfg.IPsec.PeerKeyRef] = espKey(0xDD)
	require.NoError(t, m.Rekey(context.Background(), cfg.Name))
	assert.Equal(t, 2, mock.xfrmUpdates, "both SAs updated in place")
	assert.Equal(t, espKey(0xCC), mock.xfrmStates[0].Aead.Key)
	assert.Equal(t, espKey(0xDD), mock.xfrmStates[1].Aead.Key)
	assert.Len(t, mock.xfrmStates, 2, "SPIs and policies untouched")
	assert.Len(t, mock.xfrmPolicies, 2)

	t.Run("unknown tunnel", func(t *testing.T) {
		var nf *ErrTunnelNotFound
		require.True(t, errors.As(m.Rekey(context.Background(), "nope"), &nf))
	})
	t.Run("update fails", func(t *testing.T) {
		mock.xfrmStateUpdateFn = func(*vnl.XfrmState) error { return errors.New("ESRCH") }
		defer func() { mock.xfrmStateUpdateFn = nil }()
		var rk *ErrRekeyFailed
		require.True(t, errors.As(m.Rekey(context.Background(), cfg.Name), &rk))
	})
	t.Run("key fetch fails", func(t *testing.T) {
		keys.err = errors.New("kms down")
		defer func() { keys.err = nil }()
		var rk *ErrRekeyFailed
		require.True(t, errors.As(m.Rekey(context.Background(), cfg.Name), &rk))
	})
	t.Run("gre has nothing to rotate", func(t *testing.T) {
		gre := TunnelConfig{Name: "gre-plain", Type: TunnelTypeGRE, Local: "192.0.2.1", Remote: "198.51.100.1", TunnelIP: "10.255.0.5/30"}
		require.NoError(t, m.EnsureTunnel(context.Background(), gre))
		var un *ErrRekeyUnsupported
		require.True(t, errors.As(m.Rekey(context.Background(), gre.Name), &un))
	})
}

func TestManager_EnsureTunnel_Uplink(t *testing.T) {
	mock := newMockNetlinkOps()
	mock.links["eth6"] = &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "eth6", Index: 6}}
	up := newUplinkManagerWithOps(testLogger(), mock)
	require.NoError(t, up.EnsureUplink(context.Background(), UplinkConfig{
		Name: "isp-a", Interface: "eth6", Table: 101, GatewayV4: "198.51.100.38", Addresses: []string{"198.51.100.36/29"},
	}))
	m := newManagerWithOps(testLogger(), mock, WithUplinks(up))

	cfg := TunnelConfig{Name: "gre-pri", Type: TunnelTypeGRE, Uplink: "isp-a", Local: "198.51.100.36", Remote: "198.51.100.100", TunnelIP: "10.255.0.1/30"}
	require.NoError(t, m.EnsureTunnel(context.Background(), cfg))

	// One source rule from the uplink, one endpoint pin from the tunnel.
	require.Len(t, mock.rules, 2)
	pin := mock.rules[1]
	assert.Equal(t, 101, pin.Table)
	assert.Equal(t, "198.51.100.36/32", pin.Src.String())
	assert.Equal(t, "198.51.100.100/32", pin.Dst.String())
	assert.Less(t, pin.Priority, mock.rules[0].Priority, "the pin outranks the source rule")

	require.NoError(t, m.RemoveTunnel(context.Background(), cfg.Name))
	assert.Len(t, mock.rules, 1, "the pin leaves with the tunnel")

	// #583 review: a tunnel whose uplink was removed first must still be
	// removable — the binding left with the uplink, so removal proceeds to
	// the link (and, for IPsec, the SAs) instead of failing on the uplink.
	t.Run("uplink removed before the tunnel", func(t *testing.T) {
		require.NoError(t, m.EnsureTunnel(context.Background(), cfg))
		require.NoError(t, up.RemoveUplink(context.Background(), "isp-a"))
		assert.Empty(t, mock.rules, "the uplink took the pin and its own rule with it")
		require.NoError(t, m.RemoveTunnel(context.Background(), cfg.Name))
		_, exists := mock.links[cfg.Name]
		assert.False(t, exists, "the tunnel link is deleted")
		_, err := m.Status(context.Background(), cfg.Name)
		var nf *ErrTunnelNotFound
		assert.True(t, errors.As(err, &nf), "got %v", err)
		// Re-create the uplink for the remaining subtests.
		require.NoError(t, up.EnsureUplink(context.Background(), UplinkConfig{
			Name: "isp-a", Interface: "eth6", Table: 101, GatewayV4: "198.51.100.38", Addresses: []string{"198.51.100.36/29"},
		}))
	})

	t.Run("unknown uplink", func(t *testing.T) {
		bad := cfg
		bad.Uplink = "isp-b"
		err := m.EnsureTunnel(context.Background(), bad)
		var uu *ErrUplinkUnknown
		require.True(t, errors.As(err, &uu), "got %v", err)
	})
	t.Run("no uplink manager", func(t *testing.T) {
		alone := newManagerWithOps(testLogger(), newMockNetlinkOps())
		var uu *ErrUplinkUnknown
		require.True(t, errors.As(alone.EnsureTunnel(context.Background(), cfg), &uu))
	})
	t.Run("bind failure tears the tunnel down", func(t *testing.T) {
		mock.ruleAddFn = func(*vnl.Rule) error { return errors.New("EINVAL") }
		defer func() { mock.ruleAddFn = nil }()
		var cf *ErrTunnelCreateFailed
		require.True(t, errors.As(m.EnsureTunnel(context.Background(), cfg), &cf))
		_, hasLink := mock.links[cfg.Name]
		assert.False(t, hasLink)
	})
}

func TestTunnelConfigEqual_Transports(t *testing.T) {
	a := ipsecConfig()
	b := ipsecConfig()
	assert.True(t, tunnelConfigEqual(a, b))
	b.IPsec.SPIIn = 0x9999
	assert.False(t, tunnelConfigEqual(a, b))
	b = ipsecConfig()
	b.Uplink = "isp-a"
	assert.False(t, tunnelConfigEqual(a, b))
	b = ipsecConfig()
	b.Transport = TransportGRE
	b.IPsec = nil
	assert.False(t, tunnelConfigEqual(a, b))
	assert.False(t, ipsecEqual(a.IPsec, nil))
	assert.True(t, ipsecEqual(nil, nil))
	assert.True(t, wireGuardEqual(nil, nil))
	assert.False(t, wireGuardEqual(&WireGuardConfig{KeyRef: "a"}, nil))
	assert.False(t, wireGuardEqual(&WireGuardConfig{KeyRef: "a"}, &WireGuardConfig{KeyRef: "b"}))
	assert.True(t, wireGuardEqual(&WireGuardConfig{KeyRef: "a", RemotePort: 1}, &WireGuardConfig{KeyRef: "a", RemotePort: 1}))
}

func TestFetchKey_Errors(t *testing.T) {
	_, err := fetchKey(context.Background(), nil, "t", "ref", 4)
	var kp *ErrKeyProviderRequired
	require.True(t, errors.As(err, &kp))
	assert.Contains(t, err.Error(), "key provider")

	km := &ErrKeyMaterial{Name: "t", KeyRef: "r", Reason: "x", Cause: errors.New("c")}
	assert.Equal(t, "c", km.Unwrap().Error())
	assert.Equal(t, "36", itoa(36))
	assert.Equal(t, "0", itoa(0))
	buf := []byte{1, 2, 3}
	zeroize(buf)
	assert.Equal(t, []byte{0, 0, 0}, buf)
}

func TestTransportErrors_Messages(t *testing.T) {
	assert.Contains(t, (&ErrTransportUnavailable{Name: "t", Transport: "wireguard", Reason: "fips"}).Error(), "fips")
	assert.Contains(t, (&ErrUplinkUnknown{Name: "t", Uplink: "isp-a"}).Error(), "isp-a")
	assert.Contains(t, (&ErrInvalidUplinkConfig{Reason: "x"}).Error(), "x")
	assert.Contains(t, (&ErrInvalidUplinkConfig{Name: "isp-a", Reason: "x"}).Error(), "isp-a")
	assert.Contains(t, (&ErrUplinkNotFound{Name: "isp-a"}).Error(), "isp-a")
	op := &ErrUplinkOperationFailed{Name: "isp-a", Operation: "op", Cause: errors.New("c")}
	assert.Contains(t, op.Error(), "op")
	assert.Equal(t, "c", op.Unwrap().Error())
	rk := &ErrRekeyFailed{Name: "t", Cause: errors.New("c")}
	assert.Equal(t, "c", rk.Unwrap().Error())
	assert.Contains(t, (&ErrRekeyUnsupported{Name: "t", Transport: "gre"}).Error(), "gre")
}

func TestManager_RemoveTunnel_IPsecPolicyFailureIsReported(t *testing.T) {
	mock := newMockNetlinkOps()
	cfg := ipsecConfig()
	m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)))
	require.NoError(t, m.EnsureTunnel(context.Background(), cfg))
	mock.xfrmPolicyDelFn = func(*vnl.XfrmPolicy) error { return errors.New("EPERM") }
	err := m.RemoveTunnel(context.Background(), cfg.Name)
	var rf *ErrTunnelRemoveFailed
	require.True(t, errors.As(err, &rf), "got %v", err)
	assert.Empty(t, mock.xfrmStates, "SAs are still torn down so no key stays in the kernel")
}
