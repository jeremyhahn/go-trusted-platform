//go:build integration

package ipsec

import (
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fabric addresses (TEST-NET-1).
const (
	addrA = "192.0.2.1"
	addrB = "192.0.2.2"
)

// capNetAdmin is CAP_NET_ADMIN's bit in /proc/<pid>/status CapEff.
const capNetAdmin = 12

// espState is one SA from `ip xfrm state`.
type espState struct {
	src, dst, spi, mode, aead string
	packets                   int
}

var (
	xfrmHeader  = regexp.MustCompile(`^src (\S+) dst (\S+)$`)
	xfrmProto   = regexp.MustCompile(`proto esp spi (0x[0-9a-f]+)\S* .*mode (\S+)`)
	xfrmAEAD    = regexp.MustCompile(`aead (\S+) 0x[0-9a-f]+ \(\d+ bits\) (\d+)`)
	xfrmPackets = regexp.MustCompile(`(\d+)\(packets\)`)
)

// espStates parses `ip -s xfrm state`.
func espStates(out string) []espState {
	var states []espState
	var cur *espState
	seenLifetimeCurrent := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if m := xfrmHeader.FindStringSubmatch(trimmed); m != nil && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " ") {
			states = append(states, espState{src: m[1], dst: m[2]})
			cur = &states[len(states)-1]
			seenLifetimeCurrent = false
			continue
		}
		if cur == nil {
			continue
		}
		if m := xfrmProto.FindStringSubmatch(trimmed); m != nil {
			cur.spi, cur.mode = m[1], m[2]
		}
		if m := xfrmAEAD.FindStringSubmatch(trimmed); m != nil {
			cur.aead = m[1] + "/" + m[2]
		}
		if strings.HasPrefix(trimmed, "lifetime current:") {
			seenLifetimeCurrent = true
			continue
		}
		if seenLifetimeCurrent {
			if m := xfrmPackets.FindStringSubmatch(trimmed); m != nil {
				cur.packets, _ = strconv.Atoi(m[1]) // the regexp admits digits only
				seenLifetimeCurrent = false
			}
		}
	}
	return states
}

// pair brings up two peers, each with its own token and key, certified by
// one CA, and configured for each other. Charon is started on both.
func pair(t *testing.T, ctx context.Context) (*peer, *peer) {
	t.Helper()
	in := requireInputs(t)
	t.Logf("peers: %s", in.arch)
	a := newPeer(t, ctx, in, "a", addrA)
	b := newPeer(t, ctx, in, "b", addrB)
	link(t, ctx, a, b)
	ca := newTestCA(t)
	for i, p := range []*peer{a, b} {
		p.startModuleHost(t, ctx)
		p.pub = p.provisionToken(t, ctx)
		other := b
		if p == b {
			other = a
		}
		p.configure(t, ca, ca.issue(t, p, p.pub, int64(i+2)), other)
		p.startCharon(t, ctx)
	}
	return a, b
}

// loadAll loads a peer's swanctl configuration and asserts the private key
// came from the token, not a file.
func loadAll(t *testing.T, ctx context.Context, p *peer) {
	t.Helper()
	out, err := p.swanctl(ctx, "--load-all")
	require.NoError(t, err, "%s: swanctl --load-all\n%s", p.name, p.log())
	t.Logf("%s: swanctl --load-all:\n%s", p.name, out)
	assert.Regexp(t, `loaded key \S+ from token`, out, "%s: the IKE key must be loaded from the PKCS#11 token", p.name)
	// The package has no x509 plugin: the openssl plugin decodes X.509
	// certificates and CRLs (openssl_plugin.c CERT_DECODE CERT_X509,
	// CERT_X509_CRL). Both certificates must load, and charon must report
	// neither decoder missing.
	assert.Contains(t, out, "loaded certificate from '/etc/swanctl/x509/vtep.pem'", p.name)
	assert.Contains(t, out, "loaded certificate from '/etc/swanctl/x509ca/ca.pem'", p.name)
	assert.NotRegexp(t, `(?m)unmet dependency: CERT_DECODE:X509(_CRL)?$`, p.log(), "%s: X.509 or CRL decoding is unavailable", p.name)
}

// TestESPTransportThroughPKCS11Module brings up two musl charon peers
// that authenticate IKEv2 with ECDSA keys held behind the go-xkms module and
// asserts the kernel holds the transport-mode AES-GCM ESP SAs both ways,
// that traffic flows through them, and that charon runs unprivileged.
func TestESPTransportThroughPKCS11Module(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	a, b := pair(t, ctx)
	loadAll(t, ctx, a)
	loadAll(t, ctx, b)

	out, err := a.swanctl(ctx, "--initiate", "--ike", "vtep-b", "--child", "fabric", "--timeout", "60")
	require.NoError(t, err, "initiate\n%s\n--- a ---\n%s\n--- b ---\n%s", out, a.log(), b.log())
	assert.Contains(t, out, "initiate completed successfully")

	// Both sides signed with the token key and verified the other's.
	for _, p := range []*peer{a, b} {
		log := p.log()
		assert.Regexp(t, `authentication of '`+regexp.QuoteMeta(p.addr)+`' \(myself\) with ECDSA\S* successful`, log, "%s signed with its token key", p.name)
	}
	assert.Regexp(t, `authentication of '`+regexp.QuoteMeta(addrB)+`' with ECDSA\S* successful`, a.log())
	assert.Regexp(t, `authentication of '`+regexp.QuoteMeta(addrA)+`' with ECDSA\S* successful`, b.log())
	sas, err := a.swanctl(ctx, "--list-sas")
	require.NoError(t, err)
	t.Logf("a: swanctl --list-sas:\n%s", sas)
	assert.Contains(t, sas, "ESTABLISHED")
	assert.Contains(t, sas, "KE1_ML_KEM_768", "the IKE SA uses the ML-KEM-768 hybrid key exchange")

	// Traffic between the fabric addresses goes through the SAs.
	mustRun(t, ctx, "ip", "netns", "exec", a.netns, "ping", "-c", "3", "-W", "2", addrB)

	for _, p := range []*peer{a, b} {
		out := mustRun(t, ctx, "ip", "-n", p.netns, "-s", "xfrm", "state")
		// The raw output carries the SA keys; log what was parsed instead.
		states := espStates(out)
		t.Logf("%s: ESP SAs: %+v", p.name, states)
		require.Len(t, states, 2, "%s holds one inbound and one outbound ESP SA", p.name)
		for _, s := range states {
			assert.Equal(t, "transport", s.mode, "%s: SA %s", p.name, s.spi)
			assert.Equal(t, "rfc4106(gcm(aes))/128", s.aead, "%s: SA %s is AES-GCM with a 16-byte ICV", p.name, s.spi)
			assert.Positive(t, s.packets, "%s: SA %s %s->%s carried the ping", p.name, s.spi, s.src, s.dst)
		}
		assert.Contains(t, out, "anti-replay esn context", "%s: the inbound SA uses extended sequence numbers", p.name)
		assert.Contains(t, out, "replay_window 1024", "%s: the inbound SA's replay window is 1024", p.name)
		policies := mustRun(t, ctx, "ip", "-n", p.netns, "xfrm", "policy")
		assert.Contains(t, policies, "proto esp", "%s: the policies require ESP", p.name)
	}
	// The SPIs agree crosswise: a's outbound SA is b's inbound one.
	spis := func(p *peer) map[string]string {
		m := map[string]string{}
		for _, s := range espStates(mustRun(t, ctx, "ip", "-n", p.netns, "xfrm", "state")) {
			m[s.src+">"+s.dst] = s.spi
		}
		return m
	}
	assert.Equal(t, spis(a), spis(b))

	// charon dropped root after start-up, keeping CAP_NET_ADMIN.
	for _, p := range []*peer{a, b} {
		uid, gid := p.lookupUser(t, "strongswan")
		status := p.charonStatus(t)
		assert.Equal(t, strings.Fields(status["Uid"]), []string{strconv.Itoa(uid), strconv.Itoa(uid), strconv.Itoa(uid), strconv.Itoa(uid)}, "%s: charon runs as strongswan", p.name)
		assert.Equal(t, strings.Fields(status["Gid"])[1], strconv.Itoa(gid), "%s: charon's effective group is strongswan", p.name)
		capEff, err := strconv.ParseUint(status["CapEff"], 16, 64)
		require.NoError(t, err)
		t.Logf("%s: charon CapEff=%#x", p.name, capEff)
		assert.Equal(t, uint64(1)<<capNetAdmin, capEff, "%s: charon keeps CAP_NET_ADMIN and nothing else", p.name)

		// The VICI socket is the platform user's alone: charon created it for
		// its own user and the packaged service handed it over at mode 0600.
		info, err := os.Stat(p.path(viciSocket))
		require.NoError(t, err)
		st, ok := info.Sys().(*syscall.Stat_t)
		require.True(t, ok)
		platformUID, platformGID := p.lookupUser(t, platformUser)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "%s: VICI socket mode", p.name)
		assert.Equal(t, []uint32{uint32(platformUID), uint32(platformGID)}, []uint32{st.Uid, st.Gid}, "%s: VICI socket owner", p.name)

		// The module host's socket is reachable by charon's group and no one else.
		info, err = os.Stat(p.path(p11Socket))
		require.NoError(t, err)
		st, ok = info.Sys().(*syscall.Stat_t)
		require.True(t, ok)
		assert.Equal(t, os.FileMode(0o660), info.Mode().Perm(), "%s: p11-kit socket mode", p.name)
		assert.Equal(t, gid, int(st.Gid), "%s: p11-kit socket group is charon's", p.name)
	}
}

// TestUntrustedPeerIsRefused gives b a certificate from a CA a does not
// trust: the exchange must fail and no SA may reach the kernel.
func TestUntrustedPeerIsRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	a, b := pair(t, ctx)

	// Re-issue b's certificate from a second CA and make b trust only it,
	// so each side holds a valid chain the other cannot build.
	rogue := newTestCA(t)
	b.writeFile(t, "/etc/swanctl/x509ca/ca.pem", rogue.pem, 0o644)
	b.writeFile(t, "/etc/swanctl/x509/vtep.pem", rogue.issue(t, b, b.pub, 99), 0o644)
	loadAll(t, ctx, a)
	loadAll(t, ctx, b)

	out, err := a.swanctl(ctx, "--initiate", "--ike", "vtep-b", "--child", "fabric", "--timeout", "30")
	require.Error(t, err, "an untrusted peer must not establish\n%s", out)
	assert.NotContains(t, out, "initiate completed successfully")
	for _, p := range []*peer{a, b} {
		states := espStates(mustRun(t, ctx, "ip", "-n", p.netns, "xfrm", "state"))
		assert.Empty(t, states, "%s: no SA may be installed for an unauthenticated peer", p.name)
	}
}
