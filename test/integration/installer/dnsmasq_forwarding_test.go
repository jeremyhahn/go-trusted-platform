//go:build integration

// Runtime proof that the installer's dnsmasq.conf forwards the internal
// zone (issue #131). #128/#130 stopped emitting `local=/<domain>/` on any
// node with an upstream route; their unit tests only inspect the rendered
// text. This suite runs a real dnsmasq on exactly what the installer
// writes (installer.BuildDNSMasqConf), points its upstream at a stub DNS
// server, and asserts that a query for a name in the internal zone reaches
// the stub. The regression case adds `local=/<domain>/` back and asserts
// the same query is answered locally and never forwarded.
package installer

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	installerpkg "github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

const (
	internalDomain = "example.internal"

	// internalName is a name in the internal zone that /etc/hosts does
	// not carry, so only the upstream can answer it.
	internalName = "cp." + internalDomain + "."

	// barrierName is outside the internal zone; every node shape routes
	// it to the same unscoped upstream.
	barrierName = "barrier.example.com."

	// suiteTimeout bounds every wait: dnsmasq start-up, each query and
	// each stub receive.
	suiteTimeout = 30 * time.Second
)

// stubAnswer is the address the stub upstream answers every A query with.
var stubAnswer = net.IPv4(192, 0, 2, 53)

// nodeShape is one installer dnsmasq configuration seen in the templates.
type nodeShape struct {
	name string
	// upstreamHost is the address the stub upstream listens on. The
	// worker's control plane is modelled by a second loopback address so
	// the route is not the address dnsmasq itself listens on.
	upstreamHost string
}

var nodeShapes = []nodeShape{
	// Control plane: platformd serves the zone on this node's loopback
	// (configs/platform/cluster/server*.yaml: 127.0.0.1:9053).
	{name: "ControlPlaneLoopbackUpstream", upstreamHost: "127.0.0.1"},
	// Worker: the zone is served by the control plane over the network
	// (configs/platform/cluster/client*.yaml: 10.0.1.1:9053).
	{name: "WorkerRemoteUpstream", upstreamHost: "127.0.0.2"},
}

// TestDNSMasqForwardsInternalZone proves, for every node shape, that the
// rendered config forwards an internal-zone query to the upstream.
func TestDNSMasqForwardsInternalZone(t *testing.T) {
	for _, shape := range nodeShapes {
		t.Run(shape.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), suiteTimeout)
			defer cancel()

			stub := startUpstreamStub(t, shape.upstreamHost)
			conf := renderInstallerConf(stub.addr)
			require.NotContains(t, conf, "local=/",
				"the installer must not declare a forwarded zone local")

			resolver := startDNSMasq(t, ctx, conf)
			resp := queryA(t, ctx, resolver, internalName)

			require.Equal(t, dns.RcodeSuccess, resp.Rcode,
				"dnsmasq answered %s", dns.RcodeToString[resp.Rcode])
			require.Len(t, resp.Answer, 1)
			answer, ok := resp.Answer[0].(*dns.A)
			require.True(t, ok, "answer is %T, want *dns.A", resp.Answer[0])
			assert.True(t, answer.A.Equal(stubAnswer),
				"answer %s did not come from the upstream", answer.A)
			assert.Equal(t, internalName, stub.nextQuery(t, ctx),
				"the internal-zone query did not reach the upstream")
		})
	}
}

// TestDNSMasqLocalDirectiveBlackholesInternalZone is the #128 regression
// case: the same config with `local=/<domain>/` added answers the
// internal-zone query itself and never forwards it.
func TestDNSMasqLocalDirectiveBlackholesInternalZone(t *testing.T) {
	for _, shape := range nodeShapes {
		t.Run(shape.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), suiteTimeout)
			defer cancel()

			stub := startUpstreamStub(t, shape.upstreamHost)
			conf := renderInstallerConf(stub.addr) + "local=/" + internalDomain + "/\n"

			resolver := startDNSMasq(t, ctx, conf)
			resp := queryA(t, ctx, resolver, internalName)
			require.Equal(t, dns.RcodeNameError, resp.Rcode,
				"local= must answer the zone itself with NXDOMAIN, got %s",
				dns.RcodeToString[resp.Rcode])

			// dnsmasq handles queries in order on one thread, and it has
			// already answered the internal query. A later query that is
			// forwarded is therefore the first thing the stub may see: if
			// the internal query had been forwarded, it would arrive first.
			resp = queryA(t, ctx, resolver, barrierName)
			require.Equal(t, dns.RcodeSuccess, resp.Rcode,
				"the barrier query must be forwarded, got %s",
				dns.RcodeToString[resp.Rcode])
			assert.Equal(t, barrierName, stub.nextQuery(t, ctx),
				"the internal-zone query reached the upstream despite local=")
		})
	}
}

// renderInstallerConf renders dnsmasq.conf through the installer's own
// generator. The upstream uses the templates' `host:port` shorthand, so
// the generator's normalization to dnsmasq's `#` form is exercised too.
func renderInstallerConf(upstream string) string {
	return installerpkg.BuildDNSMasqConf(&installerpkg.DNSMasqConfig{
		Enabled:         true,
		UpstreamServers: []string{upstream},
		LocalDomain:     internalDomain,
	})
}

// upstreamStub is a UDP DNS server that records the name of every query it
// receives and answers A queries with stubAnswer.
type upstreamStub struct {
	t       *testing.T
	addr    string
	queries chan string
}

// startUpstreamStub listens on a free UDP port of host and serves until the
// test ends.
func startUpstreamStub(t *testing.T, host string) *upstreamStub {
	t.Helper()

	conn, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	require.NoError(t, err, "listen for the stub upstream on %s", host)

	stub := &upstreamStub{
		t:       t,
		addr:    conn.LocalAddr().String(),
		queries: make(chan string, 16),
	}
	started := make(chan struct{})
	served := make(chan error, 1)
	server := &dns.Server{
		PacketConn:        conn,
		Handler:           dns.HandlerFunc(stub.serveDNS),
		NotifyStartedFunc: func() { close(started) },
	}
	go func() { served <- server.ActivateAndServe() }()

	select {
	case <-started:
	case err := <-served:
		t.Fatalf("stub upstream on %s stopped before it started: %v", stub.addr, err)
	}
	t.Cleanup(func() {
		require.NoError(t, server.Shutdown())
		require.NoError(t, <-served)
	})
	return stub
}

func (s *upstreamStub) serveDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	if len(req.Question) == 1 {
		question := req.Question[0]
		s.queries <- question.Name
		if question.Qtype == dns.TypeA {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   stubAnswer,
			})
		}
	}
	if err := w.WriteMsg(resp); err != nil {
		s.t.Errorf("stub upstream reply: %v", err)
	}
}

// nextQuery returns the name of the next query the stub received.
func (s *upstreamStub) nextQuery(t *testing.T, ctx context.Context) string {
	t.Helper()
	select {
	case name := <-s.queries:
		return name
	case <-ctx.Done():
		t.Fatalf("no query reached the stub upstream on %s: %v", s.addr, ctx.Err())
		return ""
	}
}

// startDNSMasq runs a real dnsmasq in the foreground on conf, listening on a
// free port of 127.0.0.1 (the generated listen-address), and returns its
// address once it has started. The process is stopped when the test ends;
// its log is printed if the test failed.
func startDNSMasq(t *testing.T, ctx context.Context, conf string) string {
	t.Helper()

	confPath := filepath.Join(t.TempDir(), "dnsmasq.conf")
	require.NoError(t, os.WriteFile(confPath, []byte(conf), 0o600))
	port := freePort(t)

	procCtx, stop := context.WithCancel(context.Background())
	cmd := exec.CommandContext(procCtx, "dnsmasq",
		"--no-daemon",
		"--conf-file="+confPath,
		"--port="+port,
		"--log-facility=-",
		"--log-queries",
	)
	stderr, err := cmd.StderrPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start(), "start dnsmasq (installed in the devcontainer image)")

	var logMu sync.Mutex
	var logLines []string
	started := make(chan struct{})
	exited := make(chan struct{})
	var waitErr error
	go func() {
		scanner := bufio.NewScanner(stderr)
		signalled := false
		for scanner.Scan() {
			line := scanner.Text()
			logMu.Lock()
			logLines = append(logLines, line)
			logMu.Unlock()
			if !signalled && strings.Contains(line, "started, version") {
				close(started)
				signalled = true
			}
		}
		waitErr = cmd.Wait()
		close(exited)
	}()

	dnsmasqLog := func() string {
		logMu.Lock()
		defer logMu.Unlock()
		return strings.Join(logLines, "\n")
	}
	t.Cleanup(func() {
		stop()
		<-exited
		if t.Failed() {
			t.Logf("dnsmasq.conf:\n%s\ndnsmasq log:\n%s", conf, dnsmasqLog())
		}
	})

	select {
	case <-started:
	case <-exited:
		t.Fatalf("dnsmasq exited before it started: %v\n%s", waitErr, dnsmasqLog())
	case <-ctx.Done():
		t.Fatalf("dnsmasq did not start: %v\n%s", ctx.Err(), dnsmasqLog())
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// freePort returns a port of 127.0.0.1 that is free for UDP at the time of
// the call.
func freePort(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	port := conn.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, conn.Close())
	return strconv.Itoa(port)
}

// queryA sends an A query for name to server over UDP.
func queryA(t *testing.T, ctx context.Context, server, name string) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	client := &dns.Client{Net: "udp"}
	resp, _, err := client.ExchangeContext(ctx, req, server)
	require.NoError(t, err, "query %s via %s", name, server)
	return resp
}
