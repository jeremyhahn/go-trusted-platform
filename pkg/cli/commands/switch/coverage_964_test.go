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

package switchcmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/switchwire"
)

// recordedRequest is what the fake platformd saw for one call.
type recordedRequest struct {
	method string
	path   string
	body   string
}

// fakeSwitchAPI serves the platformd switch REST surface in memory. Every
// request is recorded; status is the HTTP status returned for every route.
type fakeSwitchAPI struct {
	status   int
	ports    []*switchwire.PortStatus
	requests []recordedRequest
}

func (f *fakeSwitchAPI) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		f.requests = append(f.requests, recordedRequest{method: r.Method, path: r.URL.EscapedPath(), body: string(body)})

		if f.status != http.StatusOK {
			http.Error(w, "switch unreachable", f.status)
			return
		}

		var payload interface{}
		switch r.URL.EscapedPath() {
		case "/api/v1/switches/core-01/ports":
			payload = f.ports
		case "/api/v1/switches/core-01/ports/Eth1%2F3":
			payload = f.ports[0]
		}
		assert.NoError(t, json.NewEncoder(w).Encode(restwire.WebServiceResponse{
			Code: http.StatusOK, Success: true, Payload: payload,
		}))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func samplePorts() []*switchwire.PortStatus {
	return []*switchwire.PortStatus{
		{
			Port: "Eth1/3", Mode: switchwire.PortModeTrunk, AccessVLAN: 1,
			TrunkVLANs: []uint16{10, 20}, NativeVLAN: 99,
			Enabled: true, LinkUp: false, Description: "uplink-a",
		},
		{Port: "Eth1/4", Mode: switchwire.PortModeAccess, AccessVLAN: 200, Enabled: false, LinkUp: true},
	}
}

func flagsFor(format cli.OutputFormat) func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: format, NoColor: true}
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what
// fn wrote alongside fn's error.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)

	orig := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		out, readErr := io.ReadAll(r)
		assert.NoError(t, readErr)
		done <- out
	}()

	runErr := fn()
	os.Stdout = orig
	require.NoError(t, w.Close())
	out := <-done
	require.NoError(t, r.Close())
	return string(out), runErr
}

// writeCertPair writes a self-signed ECDSA certificate and its key as PEM
// files in a per-test temporary directory.
func writeCertPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "switch-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

// remoteFlags returns CommonFlags whose context carries the given remote.
func remoteFlags(remote *cli.RemoteContext) func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{GetContext: func() (*cli.Context, error) {
			return &cli.Context{Remote: remote}, nil
		}}
	}
}

func TestRunListPorts_RendersEachOutputFormat(t *testing.T) {
	tests := []struct {
		name   string
		format cli.OutputFormat
		check  func(t *testing.T, out string)
	}{
		{"table joins trunk VLANs", cli.OutputFormatTable, func(t *testing.T, out string) {
			assert.Contains(t, out, "Eth1/3")
			assert.Contains(t, out, "10,20")
			assert.Contains(t, out, "uplink-a")
			assert.Contains(t, out, "200")
		}},
		{"json round-trips the ports", cli.OutputFormatJSON, func(t *testing.T, out string) {
			var got []*switchwire.PortStatus
			require.NoError(t, json.Unmarshal([]byte(out), &got))
			assert.Equal(t, samplePorts(), got)
		}},
		{"yaml names every port", cli.OutputFormatYAML, func(t *testing.T, out string) {
			assert.Contains(t, out, "Eth1/3")
			assert.Contains(t, out, "Eth1/4")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeSwitchAPI{status: http.StatusOK, ports: samplePorts()}
			srv := api.start(t)
			flags := &switchFlags{serverURL: srv.URL, switchName: "core-01"}

			out, err := captureStdout(t, func() error { return runListPorts(flags, flagsFor(tt.format)) })
			require.NoError(t, err)
			require.Len(t, api.requests, 1)
			assert.Equal(t, http.MethodGet, api.requests[0].method)
			assert.Equal(t, "/api/v1/switches/core-01/ports", api.requests[0].path)
			tt.check(t, out)
		})
	}
}

func TestRunPortStatus_RendersEachOutputFormat(t *testing.T) {
	tests := []struct {
		name   string
		format cli.OutputFormat
		check  func(t *testing.T, out string)
	}{
		{"key-value prints optional fields", cli.OutputFormatTable, func(t *testing.T, out string) {
			assert.Contains(t, out, "Trunk VLANs")
			assert.Contains(t, out, "10, 20")
			assert.Contains(t, out, "Native VLAN")
			assert.Contains(t, out, "99")
			assert.Contains(t, out, "uplink-a")
		}},
		{"json round-trips the status", cli.OutputFormatJSON, func(t *testing.T, out string) {
			var got switchwire.PortStatus
			require.NoError(t, json.Unmarshal([]byte(out), &got))
			assert.Equal(t, *samplePorts()[0], got)
		}},
		{"yaml names the port", cli.OutputFormatYAML, func(t *testing.T, out string) {
			assert.Contains(t, out, "Eth1/3")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeSwitchAPI{status: http.StatusOK, ports: samplePorts()}
			srv := api.start(t)
			flags := &switchFlags{serverURL: srv.URL, switchName: "core-01", port: "Eth1/3"}

			out, err := captureStdout(t, func() error { return runPortStatus(flags, flagsFor(tt.format)) })
			require.NoError(t, err)
			require.Len(t, api.requests, 1)
			assert.Equal(t, "/api/v1/switches/core-01/ports/Eth1%2F3", api.requests[0].path)
			tt.check(t, out)
		})
	}
}

func TestRunPortStatus_OmitsUnsetOptionalFields(t *testing.T) {
	api := &fakeSwitchAPI{status: http.StatusOK, ports: samplePorts()[1:]}
	srv := api.start(t)
	flags := &switchFlags{serverURL: srv.URL, switchName: "core-01", port: "Eth1/3"}

	out, err := captureStdout(t, func() error { return runPortStatus(flags, flagsFor(cli.OutputFormatTable)) })
	require.NoError(t, err)
	assert.Contains(t, out, "Eth1/4")
	assert.NotContains(t, out, "Trunk VLANs")
	assert.NotContains(t, out, "Native VLAN")
	assert.NotContains(t, out, "Description")
}

// portAction is one mutating switch command under test.
type portAction struct {
	name      string
	operation string
	path      string
	body      string
	text      string
	jsonKey   string
	jsonValue interface{}
	run       func(*switchFlags, func() *cli.CommonFlags) error
}

func portActions() []portAction {
	return []portAction{
		{"enable", "enable-port", "/api/v1/switches/core-01/ports/Eth1%2F3/enable", "", "Action: enable", "action", "enable", runEnablePort},
		{"disable", "disable-port", "/api/v1/switches/core-01/ports/Eth1%2F3/disable", "", "Action: disable", "action", "disable", runDisablePort},
		{"set-vlan", "set-vlan", "/api/v1/switches/core-01/ports/Eth1%2F3/vlan", `{"vlan_id":200}`, "VLAN:   200", "vlan_id", float64(200), runSetVLAN},
	}
}

func actionFlags(serverURL string) *switchFlags {
	return &switchFlags{serverURL: serverURL, switchName: "core-01", port: "Eth1/3", vlan: 200}
}

func TestPortActions_PostAndReport(t *testing.T) {
	for _, a := range portActions() {
		t.Run(a.name+"/text", func(t *testing.T) {
			api := &fakeSwitchAPI{status: http.StatusOK}
			srv := api.start(t)

			out, err := captureStdout(t, func() error { return a.run(actionFlags(srv.URL), flagsFor(cli.OutputFormatTable)) })
			require.NoError(t, err)
			require.Len(t, api.requests, 1)
			assert.Equal(t, http.MethodPost, api.requests[0].method)
			assert.Equal(t, a.path, api.requests[0].path)
			assert.Equal(t, a.body, api.requests[0].body)
			assert.Contains(t, out, "Switch: core-01")
			assert.Contains(t, out, a.text)
			assert.Contains(t, out, "Status: ok")
		})
		t.Run(a.name+"/json", func(t *testing.T) {
			api := &fakeSwitchAPI{status: http.StatusOK}
			srv := api.start(t)

			out, err := captureStdout(t, func() error { return a.run(actionFlags(srv.URL), flagsFor(cli.OutputFormatJSON)) })
			require.NoError(t, err)
			var got map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(out), &got))
			assert.Equal(t, "core-01", got["switch"])
			assert.Equal(t, "Eth1/3", got["port"])
			assert.Equal(t, a.jsonValue, got[a.jsonKey])
			assert.Equal(t, "ok", got["status"])
		})
	}
}

// commandRunners lists every switch command that talks to platformd.
func commandRunners() map[string]func(*switchFlags, func() *cli.CommonFlags) error {
	runners := map[string]func(*switchFlags, func() *cli.CommonFlags) error{
		"list-ports":  runListPorts,
		"port-status": runPortStatus,
	}
	for _, a := range portActions() {
		runners[a.operation] = a.run
	}
	return runners
}

func TestCommands_ServerErrorIsOperationFailed(t *testing.T) {
	for operation, run := range commandRunners() {
		t.Run(operation, func(t *testing.T) {
			api := &fakeSwitchAPI{status: http.StatusInternalServerError, ports: samplePorts()}
			srv := api.start(t)

			out, err := captureStdout(t, func() error { return run(actionFlags(srv.URL), flagsFor(cli.OutputFormatTable)) })
			var opErr ErrOperationFailed
			require.True(t, errors.As(err, &opErr), "got %T: %v", err, err)
			assert.Equal(t, operation, opErr.Operation)
			assert.Error(t, opErr.Cause)
			assert.Empty(t, out)
		})
	}
}

func TestCommands_BadTLSContextIsClientCreateFailed(t *testing.T) {
	bad := remoteFlags(&cli.RemoteContext{CACert: filepath.Join(t.TempDir(), "missing.pem")})
	for operation, run := range commandRunners() {
		t.Run(operation, func(t *testing.T) {
			err := run(actionFlags("https://platform.invalid"), bad)
			var createErr ErrClientCreateFailed
			require.True(t, errors.As(err, &createErr), "got %T: %v", err, err)
			var tlsErr ErrTLSConfigFailed
			assert.True(t, errors.As(createErr.Cause, &tlsErr))
		})
	}
}

func TestBuildClientTLSConfig(t *testing.T) {
	certPath, keyPath := writeCertPair(t)
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	require.NoError(t, os.WriteFile(garbage, []byte("not a certificate"), 0o600))
	missing := filepath.Join(t.TempDir(), "missing.pem")

	tests := []struct {
		name      string
		remote    *cli.RemoteContext
		wantNil   bool
		wantRoots bool
		wantCerts int
		wantErr   func(t *testing.T, err error)
	}{
		{name: "no material yields no config", remote: &cli.RemoteContext{}, wantNil: true},
		{name: "CA only sets roots", remote: &cli.RemoteContext{CACert: certPath}, wantRoots: true},
		{name: "mTLS sets roots and client cert", remote: &cli.RemoteContext{CACert: certPath, ClientCert: certPath, ClientKey: keyPath}, wantRoots: true, wantCerts: 1},
		{name: "client cert without key is ignored", remote: &cli.RemoteContext{ClientCert: certPath}},
		{name: "missing CA file", remote: &cli.RemoteContext{CACert: missing}, wantErr: func(t *testing.T, err error) {
			assert.True(t, errors.Is(err, os.ErrNotExist))
		}},
		{name: "CA file without PEM", remote: &cli.RemoteContext{CACert: garbage}, wantErr: func(t *testing.T, err error) {
			assert.IsType(t, ErrTLSConfigFailed{}, err)
		}},
		{name: "unreadable client key pair", remote: &cli.RemoteContext{ClientCert: certPath, ClientKey: missing}, wantErr: func(t *testing.T, err error) {
			assert.True(t, errors.Is(err, os.ErrNotExist))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := buildClientTLSConfig(tt.remote)
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.Nil(t, cfg)
				tt.wantErr(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, cfg)
				return
			}
			require.NotNil(t, cfg)
			assert.Equal(t, uint16(0x0304), cfg.MinVersion)
			assert.Equal(t, tt.wantRoots, cfg.RootCAs != nil)
			assert.Len(t, cfg.Certificates, tt.wantCerts)
		})
	}
}

// errContextUnavailable is returned by a GetContext that cannot load one.
type errContextUnavailable struct{}

func (errContextUnavailable) Error() string { return "context unavailable" }

func TestBuildHTTPClient_ContextSources(t *testing.T) {
	certPath, _ := writeCertPair(t)

	tests := []struct {
		name          string
		getFlags      func() *cli.CommonFlags
		wantTransport bool
	}{
		{"context error falls back to default", func() *cli.CommonFlags {
			return &cli.CommonFlags{GetContext: func() (*cli.Context, error) { return nil, errContextUnavailable{} }}
		}, false},
		{"local context uses default", remoteFlags(nil), false},
		{"remote without TLS material uses default", remoteFlags(&cli.RemoteContext{}), false},
		{"remote CA builds a TLS transport", remoteFlags(&cli.RemoteContext{CACert: certPath}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := buildHTTPClient(tt.getFlags)
			require.NoError(t, err)
			require.NotNil(t, client)
			if !tt.wantTransport {
				assert.Nil(t, client.Transport)
				return
			}
			transport, ok := client.Transport.(*http.Transport)
			require.True(t, ok)
			require.NotNil(t, transport.TLSClientConfig)
			assert.NotNil(t, transport.TLSClientConfig.RootCAs)
		})
	}
}

func TestBuildHTTPClient_BadRemoteIsTLSConfigFailed(t *testing.T) {
	client, err := buildHTTPClient(remoteFlags(&cli.RemoteContext{CACert: filepath.Join(t.TempDir(), "missing.pem")}))
	assert.Nil(t, client)
	var tlsErr ErrTLSConfigFailed
	require.True(t, errors.As(err, &tlsErr))
	assert.True(t, errors.Is(tlsErr.Cause, os.ErrNotExist))
}
