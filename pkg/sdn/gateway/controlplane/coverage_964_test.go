package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// recordingLogger keeps every message it is handed, by level.
type recordingLogger struct {
	mu    sync.Mutex
	infos []string
	warns []string
}

func (l *recordingLogger) Info(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infos = append(l.infos, msg)
}

func (l *recordingLogger) Warn(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, msg)
}

func (l *recordingLogger) Error(string, ...any) {}

// fixedApplier applies nothing and returns err.
type fixedApplier struct{ err error }

func (a fixedApplier) Apply(context.Context, *gwstate.DesiredConfig) error { return a.err }

func newStatusReporter(t *testing.T, status int, body string, collector Collector, logger Logger) *Reporter {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	r, err := NewReporter(ReporterConfig{
		CPBaseURL:  srv.URL,
		GatewayID:  "gw-test",
		HTTPClient: srv.Client(),
		Collector:  collector,
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	return r
}

func TestErrorMessagesNameTheCause(t *testing.T) {
	cause := errors.New("boom")
	wrapped := &WrappedError{Msg: "decode", Err: cause}
	cases := map[string]struct {
		err  error
		want string
	}{
		"missing field":  {ErrMissingField{Field: "GatewayID"}, "controlplane: GatewayID is required"},
		"config invalid": {&ErrConfigInvalid{Field: "base-url", Reason: "bad"}, "controlplane: invalid base-url: bad"},
		"message":        {&MessageError{Msg: "CP returned 500"}, "CP returned 500"},
		"wrapped":        {wrapped, "decode: boom"},
		"running":        {ErrAlreadyRunning{}, "controlplane: reporter already running"},
	}
	for name, tc := range cases {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("%s: Error() = %q, want %q", name, got, tc.want)
		}
	}
	if !errors.Is(wrapped, cause) {
		t.Error("WrappedError must unwrap to its cause")
	}
	if errors.Unwrap(&WrappedError{Msg: "x"}) != nil {
		t.Error("WrappedError without a cause must unwrap to nil")
	}
}

func TestReporter_PushOnceRefusesAFailedOrEmptyCollection(t *testing.T) {
	cause := errors.New("collector down")
	r := newStatusReporter(t, http.StatusOK, "", &stubCollector{err: cause}, nil)
	var wrapped *WrappedError
	if err := r.pushOnce(context.Background()); !errors.As(err, &wrapped) || wrapped.Msg != "collect" || !errors.Is(err, cause) {
		t.Fatalf("collector error: got %v, want WrappedError{collect} around the cause", err)
	}

	r = newStatusReporter(t, http.StatusOK, "", &stubCollector{}, nil)
	var msg *MessageError
	if err := r.pushOnce(context.Background()); !errors.As(err, &msg) || !strings.Contains(msg.Msg, "nil snapshot") {
		t.Fatalf("nil snapshot: got %v, want a MessageError", err)
	}
}

func TestReporter_PushOnceReportsTheCPRefusal(t *testing.T) {
	r := newStatusReporter(t, http.StatusForbidden, "not yours", &stubCollector{snap: &gwstate.Snapshot{}}, nil)
	var msg *MessageError
	if err := r.pushOnce(context.Background()); !errors.As(err, &msg) || msg.Msg != "CP returned 403: not yours" {
		t.Fatalf("got %v, want the CP's 403 and body as a MessageError", err)
	}
}

func TestReporter_PushOnceLogsTheSuccess(t *testing.T) {
	logger := &recordingLogger{}
	r := newStatusReporter(t, http.StatusOK, "", &stubCollector{snap: &gwstate.Snapshot{}}, logger)
	if err := r.pushOnce(context.Background()); err != nil {
		t.Fatalf("pushOnce: %v", err)
	}
	if len(logger.infos) != 1 || logger.infos[0] != "telemetry posted" {
		t.Fatalf("info log = %v, want one telemetry posted", logger.infos)
	}
}

func TestReporter_StartRefusesASecondLoopAndLogsFailedPushes(t *testing.T) {
	logger := &recordingLogger{}
	refused := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		select {
		case refused <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()
	r, err := NewReporter(ReporterConfig{
		CPBaseURL:  srv.URL,
		GatewayID:  "gw-test",
		Interval:   time.Hour,
		HTTPClient: srv.Client(),
		Collector:  &stubCollector{snap: &gwstate.Snapshot{}},
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Start(ctx) }()
	select {
	case <-refused:
	case err := <-done:
		t.Fatalf("Start returned %v before the first push", err)
	case <-time.After(time.Second):
		t.Fatal("the initial push never reached the control plane")
	}

	if err := r.Start(ctx); !errors.As(err, new(ErrAlreadyRunning)) {
		t.Fatalf("second Start: got %v, want ErrAlreadyRunning", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Start did not exit after cancel")
	}
	logger.mu.Lock()
	defer logger.mu.Unlock()
	if len(logger.warns) == 0 || logger.warns[0] != "initial telemetry push failed" {
		t.Fatalf("warn log = %v, want the failed initial push", logger.warns)
	}
}

func TestReporter_FetchDesiredConfigRefusesABadResponse(t *testing.T) {
	collector := &stubCollector{snap: &gwstate.Snapshot{}}
	r := newStatusReporter(t, http.StatusNotFound, "unknown gateway", collector, nil)
	var msg *MessageError
	if _, err := r.FetchDesiredConfig(context.Background()); !errors.As(err, &msg) || msg.Msg != "CP returned 404: unknown gateway" {
		t.Fatalf("404: got %v, want the CP's status and body as a MessageError", err)
	}

	r = newStatusReporter(t, http.StatusOK, "{not json", collector, nil)
	var wrapped *WrappedError
	if _, err := r.FetchDesiredConfig(context.Background()); !errors.As(err, &wrapped) || wrapped.Msg != "decode" {
		t.Fatalf("garbage body: got %v, want WrappedError{decode}", err)
	}
}

func TestReporter_FetchDesiredConfigReportsAnUnreachableCP(t *testing.T) {
	r := newStatusReporter(t, http.StatusOK, "", &stubCollector{snap: &gwstate.Snapshot{}}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.FetchDesiredConfig(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want the cancelled request's context.Canceled", err)
	}
}

func TestReconciler_LogsEachOutcome(t *testing.T) {
	doc := &gwstate.DesiredConfig{Version: "rev-1"}
	logger := &recordingLogger{}
	ok, err := NewReconciler(ReconcilerConfig{
		Fetcher:  &stubFetcher{docs: []*gwstate.DesiredConfig{doc}},
		Applier:  fixedApplier{},
		Interval: time.Hour,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	if err := ok.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	if len(logger.infos) != 1 || logger.infos[0] != "desired config reconciled" {
		t.Fatalf("info log = %v, want one reconciled", logger.infos)
	}

	failing, err := NewReconciler(ReconcilerConfig{
		Fetcher:  &stubFetcher{docs: []*gwstate.DesiredConfig{doc}},
		Applier:  fixedApplier{err: errors.New("nft refused")},
		Interval: time.Hour,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	var failed *ErrReconcileFailed
	if err := failing.ReconcileOnce(context.Background()); !errors.As(err, &failed) || failed.Stage != "apply" {
		t.Fatalf("got %v, want ErrReconcileFailed{apply}", err)
	}
	if len(logger.warns) != 1 || logger.warns[0] != "desired config apply failed" {
		t.Fatalf("warn log = %v, want one apply failure", logger.warns)
	}
}
