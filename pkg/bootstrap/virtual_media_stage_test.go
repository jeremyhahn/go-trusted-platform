package bootstrap

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// stagedPut is one per-MAC config PUT the staging sink accepted.
type stagedPut struct {
	body        string
	contentType string
}

// stagingSink is a bootstrap-container config server that records every
// per-MAC PUT and answers each key with the status the test chose.
type stagingSink struct {
	mu     sync.Mutex
	puts   map[string]stagedPut // "<mac>/<key>" -> request
	status map[string]int       // key -> status; 204 when absent
}

func (s *stagingSink) put(mac, key string) (stagedPut, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.puts[mac+"/"+key]
	return p, ok
}

func (s *stagingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.puts)
}

// newStagingSink starts the sink and returns a deployer config that
// installLogBaseURL resolves to it.
func newStagingSink(t *testing.T, status map[string]int) (*stagingSink, DeployerConfig) {
	t.Helper()
	sink := &stagingSink{puts: map[string]stagedPut{}, status: status}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /config/mac/{mac}/{key}", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("staging sink: read body: %v", err)
		}
		key := r.PathValue("key")
		code, ok := sink.status[key]
		if !ok {
			code = http.StatusNoContent
		}
		if code >= 200 && code < 300 {
			sink.mu.Lock()
			sink.puts[r.PathValue("mac")+"/"+key] = stagedPut{body: string(body), contentType: r.Header.Get("Content-Type")}
			sink.mu.Unlock()
		}
		w.WriteHeader(code)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split sink addr: %v", err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse sink port: %v", err)
	}
	return sink, DeployerConfig{Host: host, BootstrapHTTPPort: p}
}

// newStagingOrchestrator is the trust-test orchestrator (one control
// plane on 127.0.0.1) staging into sink, with the worker template at
// a temp path so resolveNodeConfig succeeds.
func newStagingOrchestrator(t *testing.T, dep DeployerConfig, ready ConfigServerReadiness) *Orchestrator {
	t.Helper()
	o := newTrustTestOrchestrator()
	o.config.Deployer = dep
	o.configServerReady = ready
	tmpl := filepath.Join(t.TempDir(), "worker.yaml")
	if err := os.WriteFile(tmpl, []byte("stage_marker: from-template\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	o.config.Templates = map[string]string{RoleWorker: tmpl}
	return o
}

func stagingWorker(macs ...string) *DiscoveredNode {
	return &DiscoveredNode{NodeConfig: NodeConfig{Hostname: "wk-01", Role: RoleWorker, MACs: macs}}
}

func TestStagePerMACConfig_WorkerStagesConfigCABundleAndPin(t *testing.T) {
	pki := newTestCPPKI(t)
	cp := startTestCPServer(t, pki, http.StatusOK, pki.caPEM)
	sink, dep := newStagingSink(t, nil)
	o := newStagingOrchestrator(t, dep, readyConfigServer{})
	pointControlPlaneAt(t, o, cp)

	// The upper-case MAC and its duplicate collapse to one path; the
	// malformed MAC sanitizes to nothing and is skipped.
	node := stagingWorker("AA:BB:CC:DD:EE:01", "aa:bb:cc:dd:ee:01", "not-a-mac")
	if err := o.stagePerMACConfig(t.Context(), node); err != nil {
		t.Fatalf("stagePerMACConfig: %v", err)
	}

	const mac = "aa-bb-cc-dd-ee-01"
	want := map[string]struct{ contentType, body string }{
		"hostname":           {"text/plain; charset=utf-8", "wk-01"},
		"ca-bundle.pem":      {"application/x-pem-file", string(pki.caPEM)},
		"bootstrap-spki-pin": {"text/plain; charset=utf-8", pki.spkiPinB},
	}
	for key, w := range want {
		got, ok := sink.put(mac, key)
		if !ok {
			t.Errorf("%s was not staged", key)
			continue
		}
		if got.contentType != w.contentType {
			t.Errorf("%s content type = %q, want %q", key, got.contentType, w.contentType)
		}
		if got.body != w.body {
			t.Errorf("%s body = %q, want %q", key, got.body, w.body)
		}
	}
	cfg, ok := sink.put(mac, "installer.yaml")
	if !ok {
		t.Fatal("installer.yaml was not staged")
	}
	if cfg.contentType != "application/yaml" || !strings.Contains(cfg.body, "stage_marker: from-template") {
		t.Errorf("installer.yaml = %q (%s), want the resolved worker template", cfg.body, cfg.contentType)
	}
	if n := sink.count(); n != 4 {
		t.Errorf("staged %d values, want 4 (one MAC path, four keys)", n)
	}
}

func TestStagePerMACConfig_ControlPlaneStagesNoTrustMaterial(t *testing.T) {
	sink, dep := newStagingSink(t, nil)
	o := newStagingOrchestrator(t, dep, readyConfigServer{})
	node := &DiscoveredNode{NodeConfig: NodeConfig{Hostname: "cp-01", Role: RoleControlPlane, MACs: []string{"aa:bb:cc:dd:ee:02"}}}

	if err := o.stagePerMACConfig(t.Context(), node); err != nil {
		t.Fatalf("stagePerMACConfig: %v", err)
	}
	if _, ok := sink.put("aa-bb-cc-dd-ee-02", "hostname"); !ok {
		t.Error("hostname was not staged")
	}
	// The CP issues its own CA, and has no template here, so only the
	// hostname is staged.
	if n := sink.count(); n != 1 {
		t.Errorf("staged %d values, want only the hostname", n)
	}
}

func TestStagePerMACConfig_UnreachableControlPlaneStillStagesHostname(t *testing.T) {
	sink, dep := newStagingSink(t, nil)
	o := newStagingOrchestrator(t, dep, notServingConfigServer{})
	o.config.Platform.ControlPlanePort = closedTCPPort(t)

	if err := o.stagePerMACConfig(t.Context(), stagingWorker("aa:bb:cc:dd:ee:03")); err != nil {
		t.Fatalf("a missing CA bundle and pin must not fail staging: %v", err)
	}
	if _, ok := sink.put("aa-bb-cc-dd-ee-03", "hostname"); !ok {
		t.Error("hostname was not staged")
	}
	for _, key := range []string{"ca-bundle.pem", "bootstrap-spki-pin"} {
		if _, ok := sink.put("aa-bb-cc-dd-ee-03", key); ok {
			t.Errorf("%s staged without a reachable control plane", key)
		}
	}
}

func TestStagePerMACConfig_PartialFailureIsBestEffort(t *testing.T) {
	sink, dep := newStagingSink(t, map[string]int{"installer.yaml": http.StatusInternalServerError})
	o := newStagingOrchestrator(t, dep, readyConfigServer{})
	o.config.Platform.ControlPlanePort = closedTCPPort(t)

	if err := o.stagePerMACConfig(t.Context(), stagingWorker("aa:bb:cc:dd:ee:04")); err != nil {
		t.Fatalf("a staged hostname makes a failed config PUT best-effort: %v", err)
	}
	if _, ok := sink.put("aa-bb-cc-dd-ee-04", "hostname"); !ok {
		t.Error("hostname was not staged")
	}
}

func TestStagePerMACConfig_EveryHostnamePutFailsReturnsFirstError(t *testing.T) {
	_, dep := newStagingSink(t, map[string]int{
		"hostname":       http.StatusServiceUnavailable,
		"installer.yaml": http.StatusInternalServerError,
	})
	o := newStagingOrchestrator(t, dep, readyConfigServer{})
	o.config.Platform.ControlPlanePort = closedTCPPort(t)

	err := o.stagePerMACConfig(t.Context(), stagingWorker("aa:bb:cc:dd:ee:05"))
	var msgErr *MessageError
	if !errors.As(err, &msgErr) {
		t.Fatalf("err = %v, want *MessageError", err)
	}
	if !strings.Contains(msgErr.Msg, "/config/mac/aa-bb-cc-dd-ee-05/hostname: status 503") {
		t.Errorf("err = %q, want the first (hostname) PUT failure", msgErr.Msg)
	}
}

func TestStagePerMACConfig_NothingToStage(t *testing.T) {
	sink, dep := newStagingSink(t, nil)
	cases := []struct {
		name string
		node *DiscoveredNode
	}{
		{"nil node", nil},
		{"blank hostname", &DiscoveredNode{NodeConfig: NodeConfig{Hostname: "  ", MACs: []string{"aa:bb:cc:dd:ee:06"}}}},
		{"no MACs", stagingWorker()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := newStagingOrchestrator(t, dep, readyConfigServer{})
			if err := o.stagePerMACConfig(t.Context(), tc.node); err != nil {
				t.Fatalf("stagePerMACConfig: %v", err)
			}
		})
	}
	if n := sink.count(); n != 0 {
		t.Errorf("staged %d values, want none", n)
	}
}

func TestStagePerMACConfig_MissingDeployerHost(t *testing.T) {
	o := newStagingOrchestrator(t, DeployerConfig{}, readyConfigServer{})

	err := o.stagePerMACConfig(t.Context(), stagingWorker("aa:bb:cc:dd:ee:07"))
	var missing ErrMissingRequiredField
	if !errors.As(err, &missing) || missing.Field != "deployer.host" {
		t.Fatalf("err = %v, want ErrMissingRequiredField{deployer.host}", err)
	}
}
