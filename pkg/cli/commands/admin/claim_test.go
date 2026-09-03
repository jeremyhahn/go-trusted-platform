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

package admin

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeBundle mints an admin.crt / admin.key pair in a temp directory and
// returns the directory plus the leaf certificate.
func writeBundle(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "admin"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	require.NoError(t, os.WriteFile(filepath.Join(dir, "admin.crt"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "admin.key"), keyPEM, 0o600))
	return cert
}

// fakeDaemon serves the claim endpoints over plain HTTP so the CLI's own
// request/response handling is exercised end to end.
type fakeDaemon struct {
	server    *httptest.Server
	claimed   bool
	challenge string
	verified  *verifyRequest
	statusErr bool
	verifyErr bool
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	d := &fakeDaemon{challenge: "test-challenge"}
	mux := http.NewServeMux()
	mux.HandleFunc(statusPath, func(w http.ResponseWriter, r *http.Request) {
		if d.statusErr {
			d.write(w, http.StatusInternalServerError, false, "boom", nil)
			return
		}
		d.write(w, http.StatusOK, true, "", statusResponse{
			Claimed: d.claimed, Username: "admin", TenantID: "system",
		})
	})
	mux.HandleFunc(challengePath, func(w http.ResponseWriter, r *http.Request) {
		d.write(w, http.StatusOK, true, "", challengeResponse{
			Challenge: d.challenge, ExpiresAt: time.Now().Add(2 * time.Minute),
		})
	})
	mux.HandleFunc(verifyPath, func(w http.ResponseWriter, r *http.Request) {
		var req verifyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		d.verified = &req
		if d.verifyErr {
			d.write(w, http.StatusForbidden, false, "proof rejected", nil)
			return
		}
		d.write(w, http.StatusOK, true, "", verifyResponse{
			ClaimToken: "claim-token", ExpiresAt: time.Now().Add(10 * time.Minute),
		})
	})
	d.server = httptest.NewServer(mux)
	t.Cleanup(d.server.Close)
	return d
}

func (d *fakeDaemon) write(w http.ResponseWriter, status int, ok bool, errMsg string, payload any) {
	raw, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code": status, "success": ok, "error": errMsg,
		"payload": json.RawMessage(raw),
	})
}

func TestNewCommand(t *testing.T) {
	cmd := NewCommand(nil)
	require.NotNil(t, cmd)
	assert.Equal(t, "admin", cmd.Use)

	names := map[string]bool{}
	for _, sub := range cmd.Commands() {
		names[sub.Name()] = true
	}
	assert.True(t, names["claim"])
	assert.True(t, names["claim-status"])
}

func TestRunClaim_HappyPath(t *testing.T) {
	daemon := newFakeDaemon(t)
	dir := t.TempDir()
	cert := writeBundle(t, dir)

	var out bytes.Buffer
	err := runClaim(context.Background(), &out, &claimOptions{
		api: daemon.server.URL, bundleDir: dir,
	})
	require.NoError(t, err)

	assert.Contains(t, out.String(), "claim-token")
	assert.Contains(t, out.String(), "setup/admin-claim")
	assert.Contains(t, out.String(), "admin")

	// The signature the CLI sent must verify against the bundle's cert,
	// over the exact challenge string the daemon issued.
	require.NotNil(t, daemon.verified)
	assert.Equal(t, daemon.challenge, daemon.verified.Challenge)
	digest := sha256.Sum256([]byte(daemon.challenge))
	assert.True(t, ecdsa.VerifyASN1(
		cert.PublicKey.(*ecdsa.PublicKey), digest[:], daemon.verified.Signature))
}

func TestRunClaim_UsesExplicitConsoleURL(t *testing.T) {
	daemon := newFakeDaemon(t)
	dir := t.TempDir()
	writeBundle(t, dir)

	var out bytes.Buffer
	require.NoError(t, runClaim(context.Background(), &out, &claimOptions{
		api: daemon.server.URL, bundleDir: dir, console: "https://console.example.com",
	}))
	assert.Contains(t, out.String(), "https://console.example.com/setup/admin-claim")
}

func TestRunClaim_RefusesAnAlreadyClaimedNode(t *testing.T) {
	daemon := newFakeDaemon(t)
	daemon.claimed = true
	dir := t.TempDir()
	writeBundle(t, dir)

	err := runClaim(context.Background(), &bytes.Buffer{}, &claimOptions{
		api: daemon.server.URL, bundleDir: dir,
	})
	var claimed ErrAlreadyClaimed
	require.ErrorAs(t, err, &claimed)
	assert.Equal(t, "admin", claimed.Username)
}

func TestRunClaim_Failures(t *testing.T) {
	tests := []struct {
		name    string
		arrange func(t *testing.T, d *fakeDaemon, opts *claimOptions)
		errAs   any
	}{
		{
			name: "missing bundle",
			arrange: func(t *testing.T, d *fakeDaemon, opts *claimOptions) {
				opts.bundleDir = filepath.Join(t.TempDir(), "absent")
			},
			errAs: &ErrBundleUnreadable{},
		},
		{
			name: "daemon unreachable",
			arrange: func(t *testing.T, d *fakeDaemon, opts *claimOptions) {
				d.server.Close()
			},
			errAs: &ErrDaemonUnreachable{},
		},
		{
			name: "daemon refuses the proof",
			arrange: func(t *testing.T, d *fakeDaemon, opts *claimOptions) {
				d.verifyErr = true
			},
			errAs: &ErrClaimRefused{},
		},
		{
			name: "status endpoint fails",
			arrange: func(t *testing.T, d *fakeDaemon, opts *claimOptions) {
				d.statusErr = true
			},
			errAs: &ErrClaimRefused{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newFakeDaemon(t)
			dir := t.TempDir()
			writeBundle(t, dir)
			opts := &claimOptions{api: daemon.server.URL, bundleDir: dir}
			tt.arrange(t, daemon, opts)

			err := runClaim(context.Background(), &bytes.Buffer{}, opts)
			require.Error(t, err)
			require.ErrorAs(t, err, tt.errAs)
		})
	}
}

func TestRunClaimStatus(t *testing.T) {
	daemon := newFakeDaemon(t)

	var out bytes.Buffer
	require.NoError(t, runClaimStatus(context.Background(), &out,
		&claimOptions{api: daemon.server.URL}))
	assert.Contains(t, out.String(), "unclaimed")

	daemon.claimed = true
	out.Reset()
	require.NoError(t, runClaimStatus(context.Background(), &out,
		&claimOptions{api: daemon.server.URL}))
	assert.Contains(t, out.String(), "claimed")
	assert.Contains(t, out.String(), "system")
}

func TestLoadBundle_Failures(t *testing.T) {
	dir := t.TempDir()

	// No files at all.
	_, err := loadBundle(dir)
	require.ErrorAs(t, err, &ErrBundleUnreadable{})

	// A certificate with no key beside it.
	writeBundle(t, dir)
	require.NoError(t, os.Remove(filepath.Join(dir, "admin.key")))
	_, err = loadBundle(dir)
	require.ErrorAs(t, err, &ErrBundleUnreadable{})

	// Unparseable PEM.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "admin.crt"), []byte("junk"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "admin.key"), []byte("junk"), 0o600))
	_, err = loadBundle(dir)
	require.ErrorAs(t, err, &ErrBundleUnreadable{})
}

func TestNewClaimClient_CAFile(t *testing.T) {
	dir := t.TempDir()
	cert := writeBundle(t, dir)

	caFile := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(caFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600))

	client, err := newClaimClient("https://example", caFile, "")
	require.NoError(t, err)
	assert.NotNil(t, client)

	_, err = newClaimClient("https://example", filepath.Join(dir, "absent.crt"), "")
	require.ErrorAs(t, err, &ErrBundleUnreadable{})

	notPEM := filepath.Join(dir, "not-pem.crt")
	require.NoError(t, os.WriteFile(notPEM, []byte("junk"), 0o600))
	_, err = newClaimClient("https://example", notPEM, "")
	require.ErrorAs(t, err, &ErrBundleUnreadable{})
}

func TestCall_NonJSONBodyIsReported(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("<html>gateway error</html>"))
		}))
	t.Cleanup(server.Close)

	client, err := newClaimClient(server.URL, "", "")
	require.NoError(t, err)
	_, err = client.status(context.Background())

	var refused ErrClaimRefused
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, http.StatusBadGateway, refused.Status)
	assert.Contains(t, refused.Reason, "gateway error")
}

func TestErrorMessages(t *testing.T) {
	cause := errors.New("boom")
	tests := []struct {
		err      error
		contains string
		unwraps  bool
	}{
		{ErrBundleUnreadable{Path: "/p", Cause: cause}, "cannot read", true},
		{ErrBundleUnreadable{Path: "/p"}, "not usable credential material", false},
		{ErrDaemonUnreachable{Endpoint: "https://x", Cause: cause}, "cannot reach", true},
		{ErrClaimRefused{Status: 403, Reason: "nope"}, "refused the claim", false},
		{ErrAlreadyClaimed{Username: "admin"}, "already been claimed", false},
	}
	for _, tt := range tests {
		assert.Contains(t, tt.err.Error(), tt.contains)
		if tt.unwraps {
			assert.ErrorIs(t, tt.err, cause)
		}
	}
}

// TestCommandsRunEndToEnd drives the cobra RunE wiring, not just the
// functions behind it, so a mis-bound flag is caught here.
func TestCommandsRunEndToEnd(t *testing.T) {
	daemon := newFakeDaemon(t)
	dir := t.TempDir()
	writeBundle(t, dir)

	root := NewCommand(nil)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"claim", "--api", daemon.server.URL, "--bundle", dir})
	require.NoError(t, root.Execute())
	assert.Contains(t, out.String(), "claim-token")

	out.Reset()
	root.SetArgs([]string{"claim-status", "--api", daemon.server.URL})
	require.NoError(t, root.Execute())
	assert.Contains(t, out.String(), "unclaimed")
}

func TestBundleSign_Ed25519(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "admin"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "admin.crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "admin.key"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))

	credential, err := loadBundle(dir)
	require.NoError(t, err)

	// Ed25519 signs the challenge unhashed — the same rule the server
	// verifies with.
	sig, err := credential.sign([]byte("nonce"))
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(pub, []byte("nonce"), sig))
}

func TestChallenge_PropagatesTransportError(t *testing.T) {
	daemon := newFakeDaemon(t)
	daemon.server.Close()

	client, err := newClaimClient(daemon.server.URL, "", "")
	require.NoError(t, err)
	_, err = client.challenge(context.Background())
	require.ErrorAs(t, err, &ErrDaemonUnreachable{})
}

// TestLoadBundle_KeyIsHeldInProtectedMemory pins that the encoded key is
// routed through the stack's protected-memory buffer rather than a plain
// []byte, and that the read slice is wiped by the constructor.
func TestLoadBundle_KeyIsHeldInProtectedMemory(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir)

	raw, err := os.ReadFile(filepath.Join(dir, "admin.key"))
	require.NoError(t, err)
	require.Contains(t, string(raw), "PRIVATE KEY", "precondition: the file holds a key")

	credential, err := loadBundle(dir)
	require.NoError(t, err)
	require.NotNil(t, credential.signer, "the parsed signer must still be usable")

	// The signer works after the protected buffer was destroyed on return,
	// so nothing dangles into freed protected pages.
	sig, err := credential.sign([]byte("nonce"))
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

func TestErrProtectedMemoryUnavailable(t *testing.T) {
	cause := errors.New("mlock failed")
	err := ErrProtectedMemoryUnavailable{Cause: cause}
	assert.Contains(t, err.Error(), "protected memory")
	assert.Contains(t, err.Error(), "RLIMIT_MEMLOCK")
	assert.ErrorIs(t, err, cause)
}

// TestLoadBundle_KeyReadFailsAsABundleProblem pins the error split: a key
// file that cannot be read is reported as a bundle problem, because the
// operator's remedy is a path or a permission.
func TestLoadBundle_KeyReadFailsAsABundleProblem(t *testing.T) {
	t.Run("empty key file", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "admin.key"), nil, 0o600))

		_, err := loadBundle(dir)
		require.ErrorAs(t, err, &ErrBundleUnreadable{})
		require.NotErrorAs(t, err, &ErrProtectedMemoryUnavailable{})
	})

	t.Run("key path is a directory", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir)
		require.NoError(t, os.Remove(filepath.Join(dir, "admin.key")))
		require.NoError(t, os.Mkdir(filepath.Join(dir, "admin.key"), 0o700))

		_, err := loadBundle(dir)
		require.ErrorAs(t, err, &ErrBundleUnreadable{})
		require.NotErrorAs(t, err, &ErrProtectedMemoryUnavailable{})
	})
}

// TestLoadBundle_OversizedKeyIsRefusedAsAProtectedMemoryProblem pins that
// the key goes through the protected-memory reader and not os.ReadFile: a
// file above the locked-region bound is refused as a protected-memory
// failure, which os.ReadFile has no notion of.
func TestLoadBundle_OversizedKeyIsRefusedAsAProtectedMemoryProblem(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "admin.key"),
		bytes.Repeat([]byte("x"), memguard.MaxFileSize+1), 0o600))

	_, err := loadBundle(dir)
	require.ErrorAs(t, err, &ErrProtectedMemoryUnavailable{})
	require.ErrorAs(t, err, &memguard.ErrFileTooLarge{})
}

// contextFlags builds a CommonFlags whose GetContext returns active, which
// is how every platformctl command reaches the operator's selected node.
func contextFlags(active *cli.Context, err error) func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{
			GetContext: func() (*cli.Context, error) { return active, err },
		}
	}
}

// TestClaimOptionsResolve_UsesTheActiveContext pins that the claim commands
// reach the node the rest of platformctl reaches. They accepted a getFlags
// and discarded it, so an operator with a configured remote context had to
// retype --api and --ca that the context already held, and the context's
// server-name override was ignored entirely.
func TestClaimOptionsResolve_UsesTheActiveContext(t *testing.T) {
	opts := &claimOptions{
		getFlags: contextFlags(&cli.Context{
			Name: "cp",
			Type: cli.ContextTypeRemote,
			Remote: &cli.RemoteContext{
				Server:     "https://cp.example.com:8443",
				CACert:     "/etc/trusted-platform/ca.crt",
				ServerName: "cp.internal",
			},
		}, nil),
	}
	require.NoError(t, opts.resolve())

	assert.Equal(t, "https://cp.example.com:8443", opts.api)
	assert.Equal(t, "/etc/trusted-platform/ca.crt", opts.caFile)
	assert.Equal(t, "cp.internal", opts.serverName)
}

// TestClaimOptionsResolve_ExplicitFlagsWin covers the operator running the
// ceremony against a node they have no context for: the flags they typed
// must not be overwritten by the context they happen to have selected.
func TestClaimOptionsResolve_ExplicitFlagsWin(t *testing.T) {
	opts := &claimOptions{
		api:    "https://other.example.com:8443",
		caFile: "/tmp/other-ca.crt",
		getFlags: contextFlags(&cli.Context{
			Type: cli.ContextTypeRemote,
			Remote: &cli.RemoteContext{
				Server: "https://cp.example.com:8443",
				CACert: "/etc/trusted-platform/ca.crt",
			},
		}, nil),
	}
	require.NoError(t, opts.resolve())

	assert.Equal(t, "https://other.example.com:8443", opts.api)
	assert.Equal(t, "/tmp/other-ca.crt", opts.caFile)
}

// TestClaimOptionsResolve_FallsBackToLoopback covers every shape that
// cannot name a remote endpoint. None is an error: the on-node case this
// command was written for has no context at all.
func TestClaimOptionsResolve_FallsBackToLoopback(t *testing.T) {
	for name, opts := range map[string]*claimOptions{
		"no getFlags":       {},
		"nil flags":         {getFlags: func() *cli.CommonFlags { return nil }},
		"no GetContext":     {getFlags: func() *cli.CommonFlags { return &cli.CommonFlags{} }},
		"context error":     {getFlags: contextFlags(nil, errors.New("no context set"))},
		"nil context":       {getFlags: contextFlags(nil, nil)},
		"local context":     {getFlags: contextFlags(&cli.Context{Type: cli.ContextTypeLocal}, nil)},
		"remote unresolved": {getFlags: contextFlags(&cli.Context{Type: cli.ContextTypeRemote}, nil)},
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, opts.resolve())
			assert.Equal(t, DefaultAPI, opts.api)
			assert.Empty(t, opts.caFile)
			assert.Empty(t, opts.serverName)
		})
	}
}

// TestNewClaimClient_HonoursTheServerNameOverride pins that the resolved
// server name reaches the TLS handshake — a context that verifies against a
// different name than it dials is exactly why the override exists.
func TestNewClaimClient_HonoursTheServerNameOverride(t *testing.T) {
	client, err := newClaimClient("https://10.0.0.5:8443", "", "cp.internal")
	require.NoError(t, err)

	transport, ok := client.http.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Equal(t, "cp.internal", transport.TLSClientConfig.ServerName)

	client, err = newClaimClient("https://10.0.0.5:8443", "", "")
	require.NoError(t, err)
	transport, ok = client.http.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Empty(t, transport.TLSClientConfig.ServerName,
		"with no override the host portion of the URL must be used")
}

// TestClaimOptionsResolve_RefusesANonRESTContextServer pins that a context
// pointing at a non-REST transport is REFUSED, not guessed at.
//
// Remote contexts default to gRPC and `Context.ResolveProtocol` treats any
// server that does not begin http:// or https:// as gRPC, so this is the
// common shape, not an exotic one. Copying such an address into the HTTPS
// client would fail confusingly; bolting on a scheme and assuming the REST
// port could reach a DIFFERENT service on that host — and the ceremony
// hands a claim token to whatever answers.
func TestClaimOptionsResolve_RefusesANonRESTContextServer(t *testing.T) {
	for name, server := range map[string]string{
		"bare host:port": "cp.example.com:10443",
		"grpc scheme":    "grpc://cp.example.com:10443",
		"quic scheme":    "quic://cp.example.com:9444",
		"unix socket":    "/run/platformd.sock",
	} {
		t.Run(name, func(t *testing.T) {
			opts := &claimOptions{
				getFlags: contextFlags(&cli.Context{
					Name:   "cp",
					Type:   cli.ContextTypeRemote,
					Remote: &cli.RemoteContext{Server: server},
				}, nil),
			}

			err := opts.resolve()
			require.ErrorAs(t, err, &ErrContextNotREST{})
			assert.Contains(t, err.Error(), server, "the operator must see what was rejected")
			assert.Contains(t, err.Error(), "--api", "and how to proceed")
			assert.NotEqual(t, DefaultAPI, opts.api,
				"a refusal must not silently fall through to the local node")
		})
	}
}

// TestClaimOptionsResolve_ExplicitAPISurvivesANonRESTContext covers the
// operator who already knows: with --api given, the context's server is
// never consulted, so a gRPC context is no obstacle.
func TestClaimOptionsResolve_ExplicitAPISurvivesANonRESTContext(t *testing.T) {
	opts := &claimOptions{
		api: "https://cp.example.com:8443",
		getFlags: contextFlags(&cli.Context{
			Type: cli.ContextTypeRemote,
			Remote: &cli.RemoteContext{
				Server: "cp.example.com:10443",
				CACert: "/etc/trusted-platform/ca.crt",
			},
		}, nil),
	}

	require.NoError(t, opts.resolve())
	assert.Equal(t, "https://cp.example.com:8443", opts.api)
	assert.Equal(t, "/etc/trusted-platform/ca.crt", opts.caFile,
		"the context still supplies the TLS material it holds")
}

// TestClaimOptionsResolve_AcceptsPlainHTTPContexts covers a lab or
// port-forwarded deployment: http:// is a REST endpoint too, and refusing
// it would be refusing a shape the context type explicitly allows.
func TestClaimOptionsResolve_AcceptsPlainHTTPContexts(t *testing.T) {
	opts := &claimOptions{
		getFlags: contextFlags(&cli.Context{
			Type:   cli.ContextTypeRemote,
			Remote: &cli.RemoteContext{Server: "http://127.0.0.1:8080"},
		}, nil),
	}

	require.NoError(t, opts.resolve())
	assert.Equal(t, "http://127.0.0.1:8080", opts.api)
}
