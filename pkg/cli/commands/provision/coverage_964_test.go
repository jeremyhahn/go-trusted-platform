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

package provision

import (
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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errFake964 is the typed failure the fakes in this file return.
type errFake964 struct{ op string }

func (e errFake964) Error() string { return "fake failure: " + e.op }

// localFlags964 returns flags whose local context points at an idle Unix
// listener; the session client itself comes from the injected factory, so
// no RPC ever reaches the socket.
func localFlags964(t *testing.T, format cli.OutputFormat) func() *cli.CommonFlags {
	t.Helper()
	// A short directory keeps the socket path under the sun_path limit.
	dir, err := os.MkdirTemp("", "p964")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	socket := filepath.Join(dir, "d.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil {
			t.Errorf("close listener: %v", closeErr)
		}
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			t.Errorf("remove temp dir: %v", rmErr)
		}
	})
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: format,
			GetContext: func() (*cli.Context, error) {
				return &cli.Context{Name: "local", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: socket}}, nil
			},
		}
	}
}

// useFakeSessionClient installs fake as the session client for the test.
func useFakeSessionClient(t *testing.T, fake sessionAPI) {
	t.Helper()
	restore := SetSessionClientFactory(func(base *cli.BaseCommand) (sessionAPI, error) {
		return fake, nil
	})
	t.Cleanup(restore)
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w

	done := make(chan []byte)
	go func() {
		data, readErr := io.ReadAll(r)
		if readErr != nil {
			t.Errorf("read captured stdout: %v", readErr)
		}
		done <- data
	}()

	runErr := fn()
	os.Stdout = orig
	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("close pipe: %v", closeErr)
	}
	return string(<-done), runErr
}

func TestRunSessionList_JSONReportsTotalAndSessions(t *testing.T) {
	useFakeSessionClient(t, &fakeSessionAPI{sessions: []*platformv1.ProvisioningSession{
		{Id: "sess-a", EkSerial: "EK-A", ProfileId: 7},
		{Id: "sess-b", Fulfilled: true},
	}})

	out, err := captureStdout(t, func() error {
		return runSessionList(localFlags964(t, cli.OutputFormatJSON))
	})
	if err != nil {
		t.Fatalf("runSessionList() error = %v", err)
	}

	var decoded struct {
		Total    int           `json:"total"`
		Sessions []sessionInfo `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if decoded.Total != 2 || len(decoded.Sessions) != 2 {
		t.Fatalf("decoded = %+v", decoded)
	}
	if decoded.Sessions[0].ID != "sess-a" || decoded.Sessions[0].ProfileID != 7 || !decoded.Sessions[1].Fulfilled {
		t.Errorf("sessions = %+v", decoded.Sessions)
	}
}

func TestRunSessionList_TableFormat(t *testing.T) {
	tests := []struct {
		name     string
		sessions []*platformv1.ProvisioningSession
		want     []string
		notWant  []string
	}{
		{
			name:     "rows with and without a profile",
			sessions: []*platformv1.ProvisioningSession{{Id: "sess-a", EkSerial: "EK-A", MacAddress: "aa:bb", ProfileId: 42}, {Id: "sess-b"}},
			want:     []string{"EK SERIAL", "sess-a", "EK-A", "aa:bb", "42", "sess-b"},
		},
		{
			name:    "no sessions",
			want:    []string{"No provisioning sessions found"},
			notWant: []string{"EK SERIAL"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFakeSessionClient(t, &fakeSessionAPI{sessions: tt.sessions})
			out, err := captureStdout(t, func() error {
				return runSessionList(localFlags964(t, cli.OutputFormatTable))
			})
			if err != nil {
				t.Fatalf("runSessionList() error = %v", err)
			}
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("table output missing %q:\n%s", w, out)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(out, w) {
					t.Errorf("table output unexpectedly contains %q:\n%s", w, out)
				}
			}
		})
	}
}

func TestRunSessionVerbs_PrintClientResult(t *testing.T) {
	tests := []struct {
		name string
		fake *fakeSessionAPI
		run  func(getFlags func() *cli.CommonFlags) error
		want map[string]any
	}{
		{
			name: "get",
			fake: &fakeSessionAPI{session: &platformv1.ProvisioningSession{Id: "sess-1", MacAddress: "aa:bb"}},
			run: func(getFlags func() *cli.CommonFlags) error {
				return runSessionGet(getFlags, "sess-1")
			},
			want: map[string]any{"id": "sess-1", "mac_address": "aa:bb"},
		},
		{
			name: "fulfill",
			fake: &fakeSessionAPI{fulfill: &platformv1.FulfillSessionResponse{Status: "fulfilled"}},
			run: func(getFlags func() *cli.CommonFlags) error {
				return runSessionFulfill(getFlags, "sess-1", "42")
			},
			want: map[string]any{"session_id": "sess-1", "profile_id": "42", "status": "fulfilled"},
		},
		{
			name: "poll pending",
			fake: &fakeSessionAPI{poll: &platformv1.PollSessionResponse{}},
			run: func(getFlags func() *cli.CommonFlags) error {
				return runSessionPoll(getFlags, "sess-1", "")
			},
			want: map[string]any{"session_id": "sess-1", "status": "pending"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFakeSessionClient(t, tt.fake)
			out, err := captureStdout(t, func() error {
				return tt.run(localFlags964(t, cli.OutputFormatJSON))
			})
			if err != nil {
				t.Fatalf("run error = %v", err)
			}
			var decoded map[string]any
			if err := json.Unmarshal([]byte(out), &decoded); err != nil {
				t.Fatalf("output is not JSON: %v\n%s", err, out)
			}
			for k, v := range tt.want {
				if decoded[k] != v {
					t.Errorf("%s = %v, want %v (output %s)", k, decoded[k], v, out)
				}
			}
		})
	}
}

func TestRunSessionFulfill_PassesParsedProfileID(t *testing.T) {
	fake := &fakeSessionAPI{fulfill: &platformv1.FulfillSessionResponse{Status: "fulfilled"}}
	useFakeSessionClient(t, fake)

	if _, err := captureStdout(t, func() error {
		return runSessionFulfill(localFlags964(t, cli.OutputFormatJSON), "sess-9", "18446744073709551615")
	}); err != nil {
		t.Fatalf("runSessionFulfill() error = %v", err)
	}
	if fake.lastFulfillSessionID != "sess-9" || fake.lastFulfillProfileID != 18446744073709551615 {
		t.Errorf("client args = %q/%d", fake.lastFulfillSessionID, fake.lastFulfillProfileID)
	}
}

func TestRunSessionFulfill_InvalidProfileIDNeverOpensClient(t *testing.T) {
	opened := false
	restore := SetSessionClientFactory(func(base *cli.BaseCommand) (sessionAPI, error) {
		opened = true
		return &fakeSessionAPI{}, nil
	})
	t.Cleanup(restore)

	err := runSessionFulfill(localFlags964(t, cli.OutputFormatJSON), "sess-1", "abc")
	var typed ErrInvalidProfileID
	if !errors.As(err, &typed) || typed.Value != "abc" {
		t.Fatalf("expected ErrInvalidProfileID for abc, got %T: %v", err, err)
	}
	if errors.Unwrap(err) == nil || !strings.Contains(err.Error(), `"abc"`) {
		t.Errorf("error should name the value and wrap the parse cause: %v", err)
	}
	if opened {
		t.Error("session client opened despite an invalid profile ID")
	}

	err = runSessionFulfill(localFlags964(t, cli.OutputFormatJSON), "sess-1", "0")
	if !errors.As(err, new(ErrProfileIDRequired)) || !strings.Contains(err.Error(), "--profile-id") {
		t.Errorf("expected ErrProfileIDRequired for 0, got %T: %v", err, err)
	}
}

// sessionVerbs964 runs each session verb with fixed, valid arguments.
var sessionVerbs964 = map[string]func(getFlags func() *cli.CommonFlags) error{
	"list":    runSessionList,
	"get":     func(f func() *cli.CommonFlags) error { return runSessionGet(f, "s") },
	"fulfill": func(f func() *cli.CommonFlags) error { return runSessionFulfill(f, "s", "1") },
	"poll":    func(f func() *cli.CommonFlags) error { return runSessionPoll(f, "s", "") },
}

func TestRunSessionVerbs_FactoryFailureIsTyped(t *testing.T) {
	cause := errFake964{op: "factory"}
	restore := SetSessionClientFactory(func(base *cli.BaseCommand) (sessionAPI, error) {
		return nil, cause
	})
	t.Cleanup(restore)

	for name, run := range sessionVerbs964 {
		t.Run(name, func(t *testing.T) {
			err := run(localFlags964(t, cli.OutputFormatJSON))
			var typed ErrSessionClientFailed
			if !errors.As(err, &typed) {
				t.Fatalf("expected ErrSessionClientFailed, got %T: %v", err, err)
			}
			if !errors.Is(err, cause) {
				t.Errorf("ErrSessionClientFailed does not unwrap to the factory cause: %v", err)
			}
			if !strings.Contains(err.Error(), "failed to create session client") {
				t.Errorf("Error() = %q", err.Error())
			}
		})
	}
}

func TestRunSessionVerbs_ClientErrorPropagates(t *testing.T) {
	cause := errFake964{op: "rpc"}
	useFakeSessionClient(t, &fakeSessionAPI{err: cause})

	for name, run := range sessionVerbs964 {
		t.Run(name, func(t *testing.T) {
			if err := run(localFlags964(t, cli.OutputFormatJSON)); !errors.Is(err, cause) {
				t.Errorf("expected the client error, got %T: %v", err, err)
			}
		})
	}
}

func TestRunSessionVerbs_NoContextFailsBeforeFactory(t *testing.T) {
	opened := false
	restore := SetSessionClientFactory(func(base *cli.BaseCommand) (sessionAPI, error) {
		opened = true
		return &fakeSessionAPI{}, nil
	})
	t.Cleanup(restore)

	for name, run := range sessionVerbs964 {
		t.Run(name, func(t *testing.T) {
			if err := run(testGetFlags()); !errors.As(err, new(cli.ErrNoContextSet)) {
				t.Errorf("expected cli.ErrNoContextSet, got %T: %v", err, err)
			}
		})
	}
	if opened {
		t.Error("session client factory called without a context")
	}
}

func TestSessionCommands_RunEDispatchesToVerb(t *testing.T) {
	useFakeSessionClient(t, &fakeSessionAPI{
		sessions: []*platformv1.ProvisioningSession{{Id: "sess-list"}},
		session:  &platformv1.ProvisioningSession{Id: "sess-get"},
		fulfill:  &platformv1.FulfillSessionResponse{Status: "fulfilled"},
		poll:     &platformv1.PollSessionResponse{Result: &platformv1.PollSessionResponse_PendingStatus{PendingStatus: "awaiting-operator"}},
	})
	getFlags := localFlags964(t, cli.OutputFormatJSON)

	tests := []struct {
		name string
		cmd  func() error
		want string
	}{
		{"list", func() error {
			c := newSessionListCommand(getFlags)
			c.SetArgs([]string{})
			return c.Execute()
		}, "sess-list"},
		{"get", func() error {
			c := newSessionGetCommand(getFlags)
			c.SetArgs([]string{"sess-get"})
			return c.Execute()
		}, "sess-get"},
		{"fulfill", func() error {
			c := newSessionFulfillCommand(getFlags)
			c.SetArgs([]string{"sess-f", "--profile-id", "42"})
			return c.Execute()
		}, "sess-f"},
		{"poll", func() error {
			c := newSessionPollCommand(getFlags)
			c.SetArgs([]string{"sess-p"})
			return c.Execute()
		}, "awaiting-operator"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := captureStdout(t, tt.cmd)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if !strings.Contains(out, tt.want) {
				t.Errorf("output missing %q:\n%s", tt.want, out)
			}
		})
	}
}

// provisionServer964 serves the nonce and config endpoints, answering the
// config request with resp (or a raw status code when code is non-zero).
func provisionServer964(t *testing.T, resp configResponse, code int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/provisioning/config/nonce", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(nonceResponse{Nonce: "nonce-964"}); err != nil {
			t.Errorf("encode nonce: %v", err)
		}
	})
	mux.HandleFunc("/api/v1/provisioning/config", func(w http.ResponseWriter, r *http.Request) {
		var req configRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode config request: %v", err)
		}
		if code != 0 {
			http.Error(w, "denied", code)
			return
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode config: %v", err)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func validFlags964(t *testing.T, serverURL string) *provisionFlags {
	t.Helper()
	return &provisionFlags{
		serverURL: serverURL,
		ekSerial:  "EK-964",
		mac:       "aa:bb:cc:dd:ee:ff",
		eabKID:    "kid",
		eabHMAC:   "hmac",
		output:    filepath.Join(t.TempDir(), "nested", "config.yaml"),
		timeout:   30,
	}
}

// configFlows964 are the two flows that fetch a nonce, request the config
// and write it when the server answers "ok".
var configFlows964 = map[string]func(*provisionFlags) error{
	"fetch-config": runFetchConfig,
	"interactive":  runInteractive,
}

func TestConfigFlows_WriteConfigOnOK(t *testing.T) {
	for name, run := range configFlows964 {
		t.Run(name, func(t *testing.T) {
			srv := provisionServer964(t, configResponse{Status: statusOK, Config: "hostname: node-964\n"}, 0)
			flags := validFlags964(t, srv.URL)

			out, err := captureStdout(t, func() error { return run(flags) })
			if err != nil {
				t.Fatalf("run error = %v", err)
			}
			data, readErr := os.ReadFile(flags.output)
			if readErr != nil || string(data) != "hostname: node-964\n" {
				t.Errorf("written config = %q err=%v", data, readErr)
			}
			if !strings.Contains(out, "Config written to "+flags.output) {
				t.Errorf("stdout = %q", out)
			}
		})
	}
}

func TestConfigFlows_Errors(t *testing.T) {
	tests := []struct {
		name    string
		resp    configResponse
		code    int
		mutate  func(*provisionFlags)
		wantErr func(error) bool
	}{
		{
			name: "unknown status",
			resp: configResponse{Status: "rejected"},
			wantErr: func(err error) bool {
				var e ErrUnexpectedStatus
				return errors.As(err, &e) && strings.Contains(e.Body, "rejected")
			},
		},
		{
			name: "server refuses config",
			code: http.StatusForbidden,
			wantErr: func(err error) bool {
				var e ErrUnexpectedStatus
				return errors.As(err, &e) && e.StatusCode == http.StatusForbidden
			},
		},
		{
			name:    "missing server URL",
			mutate:  func(f *provisionFlags) { f.serverURL = "" },
			wantErr: func(err error) bool { return errors.As(err, new(ErrServerURLRequired)) },
		},
		{
			name:    "nonce endpoint unreachable",
			mutate:  func(f *provisionFlags) { f.serverURL = "http://127.0.0.1:0" },
			wantErr: func(err error) bool { return errors.As(err, new(ErrNonceFetchFailed)) },
		},
		{
			name: "output path not writable",
			resp: configResponse{Status: statusOK, Config: "x"},
			mutate: func(f *provisionFlags) {
				blocker := filepath.Join(filepath.Dir(filepath.Dir(f.output)), "file")
				if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
					t.Fatalf("write blocker: %v", err)
				}
				f.output = filepath.Join(blocker, "config.yaml")
			},
			wantErr: func(err error) bool { return errors.As(err, new(ErrConfigWriteFailed)) },
		},
	}

	for name, run := range configFlows964 {
		for _, tt := range tests {
			t.Run(name+"/"+tt.name, func(t *testing.T) {
				srv := provisionServer964(t, tt.resp, tt.code)
				flags := validFlags964(t, srv.URL)
				if tt.mutate != nil {
					tt.mutate(flags)
				}
				if _, err := captureStdout(t, func() error { return run(flags) }); !tt.wantErr(err) {
					t.Errorf("unexpected error %T: %v", err, err)
				}
			})
		}
	}
}

func TestRunInteractive_RejectsNonPositiveTimeout(t *testing.T) {
	for _, timeout := range []int{0, -5} {
		flags := validFlags964(t, "http://127.0.0.1:0")
		flags.timeout = timeout
		var typed ErrInvalidTimeout
		if err := runInteractive(flags); !errors.As(err, &typed) || typed.Value != timeout {
			t.Errorf("timeout %d: expected ErrInvalidTimeout, got %T: %v", timeout, err, err)
		}
	}
}
