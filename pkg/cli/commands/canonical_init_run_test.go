package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gate"
)

// fakeGateClient answers Init and records whether it was called.
type fakeGateClient struct {
	resp   *gate.InitResponse
	err    error
	called bool
}

func (c *fakeGateClient) Init(_ context.Context, _ *gate.InitRequest) (*gate.InitResponse, error) {
	c.called = true
	return c.resp, c.err
}

// jsonRender is the production printer in JSON mode, so the redaction
// tests see exactly what an operator would.
func jsonRender(w io.Writer, v any) error {
	return cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, w).Print(v)
}

func TestExecuteCanonicalInit_GateFailureReturnsTypedStepError(t *testing.T) {
	cause := errors.New("gate unavailable")
	dir := t.TempDir()
	f := &canonicalInitFlags{adminBundle: filepath.Join(dir, "admin.pem")}
	var stdout, stderr bytes.Buffer

	err := executeCanonicalInit(context.Background(), &stdout, &stderr, f, &fakeGateClient{err: cause}, jsonRender)

	var stepErr *ErrInitStepFailed
	if !errors.As(err, &stepErr) || stepErr.Step != InitStepGateInit {
		t.Fatalf("want gate-init step error, got %T: %v", err, err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("error does not wrap the gate failure: %v", err)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("failure must not print, got stdout %q stderr %q", stdout.String(), stderr.String())
	}
	if names := dirEntries(t, dir); len(names) != 0 {
		t.Fatalf("failed init left files: %v", names)
	}
}

// TestExecuteCanonicalInit_StdoutSinkPrintsKeyOnce verifies that with the
// bundle on stdout, stdout is exactly the bundle and the summary goes to
// stderr without the key.
func TestExecuteCanonicalInit_StdoutSinkPrintsKeyOnce(t *testing.T) {
	var stdout, stderr bytes.Buffer
	f := &canonicalInitFlags{adminBundle: "-"}

	err := executeCanonicalInit(context.Background(), &stdout, &stderr, f, &fakeGateClient{resp: testBundleResponse()}, jsonRender)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout.String() != assembleAdminBundle(testBundleResponse()) {
		t.Fatalf("stdout is not exactly the bundle: %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "PRIVATE KEY") || strings.Contains(stderr.String(), "MIIBkey") {
		t.Fatalf("summary leaked the admin key: %q", stderr.String())
	}
	var summary initSummary
	if err := json.Unmarshal(stderr.Bytes(), &summary); err != nil {
		t.Fatalf("summary is not JSON: %v: %q", err, stderr.String())
	}
	if summary.AdminBundle != "stdout" || summary.SPKIPin != testSPKIPin || summary.CeremonyID != "ceremony-1" || summary.State != "unsealed" {
		t.Errorf("summary = %+v", summary)
	}
}

// TestExecuteCanonicalInit_FileSinkSummaryHasNoKey verifies that with a
// file sink the key is only in the 0600 file, never on stdout or stderr.
func TestExecuteCanonicalInit_FileSinkSummaryHasNoKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.pem")
	var stdout, stderr bytes.Buffer
	f := &canonicalInitFlags{adminBundle: path}

	err := executeCanonicalInit(context.Background(), &stdout, &stderr, f, &fakeGateClient{resp: testBundleResponse()}, jsonRender)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for name, out := range map[string]string{"stdout": stdout.String(), "stderr": stderr.String()} {
		if strings.Contains(out, "PRIVATE KEY") || strings.Contains(out, "MIIBkey") {
			t.Fatalf("%s leaked the admin key: %q", name, out)
		}
	}
	var summary initSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("summary is not JSON: %v: %q", err, stdout.String())
	}
	if summary.AdminBundle != path {
		t.Errorf("summary bundle = %q, want %q", summary.AdminBundle, path)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if !strings.Contains(string(body), testAdminKey) {
		t.Errorf("bundle file missing the key: %q", body)
	}
}

// TestExecuteCanonicalInit_ExistingBundleRefusedBeforeInit verifies the
// one-shot bundle is never minted when it could not be written.
func TestExecuteCanonicalInit_ExistingBundleRefusedBeforeInit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.pem")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	client := &fakeGateClient{resp: testBundleResponse()}

	err := executeCanonicalInit(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, &canonicalInitFlags{adminBundle: path}, client, jsonRender)

	var exists *ErrAdminBundleExists
	if !errors.As(err, &exists) {
		t.Fatalf("want ErrAdminBundleExists, got %T: %v", err, err)
	}
	if client.called {
		t.Fatal("init was sent although the bundle could not be written")
	}
}

// TestExecuteCanonicalInit_DirectoryBundleRefusedBeforeInit verifies a
// destination the bundle could never be moved onto stops init, even with
// --force.
func TestExecuteCanonicalInit_DirectoryBundleRefusedBeforeInit(t *testing.T) {
	path := t.TempDir()
	client := &fakeGateClient{resp: testBundleResponse()}

	err := executeCanonicalInit(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, &canonicalInitFlags{adminBundle: path, force: true}, client, jsonRender)

	var isDir *ErrAdminBundleIsDirectory
	if !errors.As(err, &isDir) || isDir.Path != path {
		t.Fatalf("want ErrAdminBundleIsDirectory{%q}, got %T: %v", path, err, err)
	}
	if client.called {
		t.Fatal("init was sent although the bundle could not be written")
	}
}

func TestExecuteCanonicalInit_EmptyBundleIsTypedError(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]*gate.InitResponse{
		"nil":          nil,
		"missing-cert": {AdminKeyPEM: testAdminKey},
		"missing-key":  {AdminCertPEM: testAdminCert},
	}
	for name, resp := range cases {
		t.Run(name, func(t *testing.T) {
			f := &canonicalInitFlags{adminBundle: filepath.Join(dir, name+".pem")}
			err := executeCanonicalInit(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, f, &fakeGateClient{resp: resp}, jsonRender)
			var emptyErr *ErrAdminBundleEmpty
			if !errors.As(err, &emptyErr) {
				t.Fatalf("want *ErrAdminBundleEmpty, got %T: %v", err, err)
			}
		})
	}
	if names := dirEntries(t, dir); len(names) != 0 {
		t.Fatalf("empty bundles left files: %v", names)
	}
}

func TestExecuteCanonicalInit_RenderFailureReturnsTypedStepError(t *testing.T) {
	render := func(io.Writer, any) error { return errors.New("printer broke") }

	err := executeCanonicalInit(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, &canonicalInitFlags{}, &fakeGateClient{resp: testBundleResponse()}, render)

	var stepErr *ErrInitStepFailed
	if !errors.As(err, &stepErr) || stepErr.Step != InitStepRenderOutput {
		t.Fatalf("want render step error, got %T: %v", err, err)
	}
}

func TestRunCanonicalInit_RemoteGateEndpointRefused(t *testing.T) {
	cmd, f := newInitCmdForTest(t, map[string]string{"gate-endpoint": "10.0.0.5:9446"})
	var out bytes.Buffer
	cmd.SetOut(&out)

	err := runCanonicalInit(cmd, f, func() *cli.CommonFlags { return &cli.CommonFlags{} })

	var stepErr *ErrInitStepFailed
	if !errors.As(err, &stepErr) || stepErr.Step != InitStepGateClient {
		t.Fatalf("want gate-client step error, got %T: %v", err, err)
	}
	var invalid *gate.ErrInvalidEndpoint
	if !errors.As(err, &invalid) {
		t.Fatalf("error does not wrap ErrInvalidEndpoint: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("failure must not print, got %q", out.String())
	}
}

// TestRunCanonicalInit_UsesLocalContextSocket drives init end to end over
// a real Unix socket named by the local context, without any SDK
// connection (none exists before unseal).
func TestRunCanonicalInit_UsesLocalContextSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "p.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var got gate.InitRequest
	mux := http.NewServeMux()
	mux.HandleFunc("POST /init", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(testBundleResponse()); err != nil {
			t.Errorf("encode: %v", err)
		}
	})
	srv := &httptest.Server{Listener: listener, Config: &http.Server{Handler: mux}}
	srv.Start()
	t.Cleanup(srv.Close)

	cmd, f := newInitCmdForTest(t, map[string]string{
		"so-pin": "so", "user-pin": "user", "barrier-strategy": "shamir", "shares": "5", "threshold": "3",
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		GetContext: func() (*cli.Context, error) {
			return &cli.Context{Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
		},
	}

	if err := runCanonicalInit(cmd, f, func() *cli.CommonFlags { return flags }); err != nil {
		t.Fatalf("runCanonicalInit: %v", err)
	}
	if got.SOPIN != "so" || got.Shares != 5 || got.Threshold != 3 || got.CredentialSealStrategy != "shamir" {
		t.Errorf("daemon received %+v", got)
	}
	if strings.Count(stdout.String(), "MIIBkey") != 1 || strings.Contains(stderr.String(), "MIIBkey") {
		t.Errorf("key must appear once, on stdout only: stdout %q stderr %q", stdout.String(), stderr.String())
	}
}

func TestResolveGateEndpoint(t *testing.T) {
	local := func() (*cli.Context, error) {
		return &cli.Context{Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: "/run/platformd.sock"}}, nil
	}
	remote := func() (*cli.Context, error) {
		return &cli.Context{Type: cli.ContextTypeRemote, Remote: &cli.RemoteContext{Server: "https://p:8443"}}, nil
	}
	missing := func() (*cli.Context, error) { return nil, errors.New("no config") }

	cases := []struct {
		name         string
		explicit     string
		loopbackHTTP bool
		flags        *cli.CommonFlags
		want         string
	}{
		{"explicit wins", "unix:///tmp/x.sock", false, &cli.CommonFlags{GetContext: local}, "unix:///tmp/x.sock"},
		{"explicit loopback with opt-in", "[::1]:9446", true, &cli.CommonFlags{GetContext: local}, "[::1]:9446"},
		{"opt-in overrides local context", "", true, &cli.CommonFlags{GetContext: local}, gate.DefaultHTTPAddr},
		{"local context socket", "", false, &cli.CommonFlags{GetContext: local}, "unix:///run/platformd.sock"},
		{"remote context uses default socket", "", false, &cli.CommonFlags{GetContext: remote}, "unix://" + platform.DefaultUnixSocket},
		{"no context uses default socket", "", false, &cli.CommonFlags{GetContext: missing}, "unix://" + platform.DefaultUnixSocket},
		{"nil flags uses default socket", "", false, nil, "unix://" + platform.DefaultUnixSocket},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveGateEndpoint(tc.explicit, tc.loopbackHTTP, tc.flags); got != tc.want {
				t.Errorf("resolveGateEndpoint = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestValidateGateTransport_LoopbackHTTPIsOptIn asserts init never sends
// the PINs over HTTP unless the operator asked for it, and refuses the
// contradiction of asking for HTTP while naming a socket.
func TestValidateGateTransport_LoopbackHTTPIsOptIn(t *testing.T) {
	cases := []struct {
		name         string
		endpoint     string
		loopbackHTTP bool
		wantErr      error
	}{
		{"default endpoint", "", false, nil},
		{"default endpoint with opt-in", "", true, nil},
		{"socket", "unix:///run/platformd.sock", false, nil},
		{"loopback with opt-in", "127.0.0.1:9446", true, nil},
		{"loopback without opt-in", "127.0.0.1:9446", false, &ErrLoopbackHTTPNotEnabled{}},
		{"socket with opt-in", "unix:///run/platformd.sock", true, &ErrLoopbackHTTPConflict{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGateTransport(tc.endpoint, tc.loopbackHTTP)
			switch want := tc.wantErr.(type) {
			case nil:
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			case *ErrLoopbackHTTPNotEnabled:
				if !errors.As(err, &want) || want.Endpoint != tc.endpoint {
					t.Fatalf("want ErrLoopbackHTTPNotEnabled for %q, got %T: %v", tc.endpoint, err, err)
				}
			case *ErrLoopbackHTTPConflict:
				if !errors.As(err, &want) || want.Endpoint != tc.endpoint {
					t.Fatalf("want ErrLoopbackHTTPConflict for %q, got %T: %v", tc.endpoint, err, err)
				}
			}
		})
	}
}

// TestNewInitCommand_LoopbackEndpointNeedsOptIn drives the command's own
// validation: a loopback --gate-endpoint without --loopback-http fails
// before anything is sent.
func TestNewInitCommand_LoopbackEndpointNeedsOptIn(t *testing.T) {
	cmd := NewInitCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	cmd.SetArgs([]string{"--so-pin", "so", "--user-pin", "user", "--gate-endpoint", gate.DefaultHTTPAddr})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	err := cmd.Execute()
	var notEnabled *ErrLoopbackHTTPNotEnabled
	if !errors.As(err, &notEnabled) {
		t.Fatalf("want ErrLoopbackHTTPNotEnabled, got %T: %v", err, err)
	}
}

// TestNewInitCommand_HelpWarnsAboutLoopbackHTTP keeps the replay warning
// where the operator chooses the transport.
func TestNewInitCommand_HelpWarnsAboutLoopbackHTTP(t *testing.T) {
	cmd := NewInitCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	flag := cmd.Flags().Lookup("loopback-http")
	if flag == nil {
		t.Fatal("init has no --loopback-http flag")
	}
	if flag.DefValue != "false" {
		t.Errorf("--loopback-http must default to false, got %q", flag.DefValue)
	}
	if !strings.Contains(flag.Usage, "WARNING") || !strings.Contains(flag.Usage, "replayed") {
		t.Errorf("--loopback-http help must warn that a lost response cannot be replayed: %q", flag.Usage)
	}
}
