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

package app

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/pkg/scheduler"
)

// fakeScheduler is an in-memory SchedulerService for unit tests.
type fakeScheduler struct {
	mu             sync.Mutex
	jobs           []*scheduler.Job
	handlers       map[string]scheduler.JobHandler
	registerErr    error
	scheduleErr    error
	listErr        error
	registerCalls  int
	scheduleCalls  int
	listCalls      int
}

func newFakeScheduler() *fakeScheduler {
	return &fakeScheduler{handlers: map[string]scheduler.JobHandler{}}
}

func (f *fakeScheduler) RegisterHandler(name string, handler scheduler.JobHandler) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registerCalls++
	if f.registerErr != nil {
		return f.registerErr
	}
	if _, ok := f.handlers[name]; ok {
		return errors.New("handler already registered: " + name)
	}
	f.handlers[name] = handler
	return nil
}

func (f *fakeScheduler) ScheduleJob(_ context.Context, job *scheduler.Job) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scheduleCalls++
	if f.scheduleErr != nil {
		return f.scheduleErr
	}
	clone := *job
	f.jobs = append(f.jobs, &clone)
	return nil
}

func (f *fakeScheduler) ListJobs(_ context.Context, q *scheduler.JobQuery) ([]*scheduler.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := []*scheduler.Job{}
	for _, j := range f.jobs {
		if q != nil {
			if q.Handler != "" && j.Handler != q.Handler {
				continue
			}
			if q.OwnerID != "" && j.OwnerID != q.OwnerID {
				continue
			}
		}
		out = append(out, j)
	}
	return out, nil
}

// stubTarget builds a CertTarget whose Current returns notAfter and
// whose Reissue records invocation + optional error.
type stubTarget struct {
	name         string
	notAfter     time.Time
	currentErr   error
	currentNil   bool
	reissueErr   error
	reissueCalls int
	mu           sync.Mutex
}

func (s *stubTarget) buildTarget() *CertTarget {
	return &CertTarget{
		Name: s.name,
		Kind: CertKindBMC,
		Current: func(context.Context) (*x509.Certificate, error) {
			if s.currentErr != nil {
				return nil, s.currentErr
			}
			if s.currentNil {
				return nil, nil
			}
			return &x509.Certificate{NotAfter: s.notAfter}, nil
		},
		Reissue: func(context.Context) error {
			s.mu.Lock()
			s.reissueCalls++
			s.mu.Unlock()
			return s.reissueErr
		},
	}
}

// --- RegisterCertRenewal: input validation ---

func TestRegisterCertRenewal_MissingScheduler(t *testing.T) {
	err := RegisterCertRenewal(context.Background(), CertRenewalRegistration{
		Registry: NewCertTargetRegistry(),
		NodeID:   "n",
	})
	if !errors.Is(err, ErrCertRenewalMissingScheduler) {
		t.Errorf("err = %v, want ErrCertRenewalMissingScheduler", err)
	}
}

func TestRegisterCertRenewal_MissingRegistry(t *testing.T) {
	err := RegisterCertRenewal(context.Background(), CertRenewalRegistration{
		Scheduler: newFakeScheduler(),
		NodeID:    "n",
	})
	if !errors.Is(err, ErrCertRenewalMissingRegistry) {
		t.Errorf("err = %v, want ErrCertRenewalMissingRegistry", err)
	}
}

func TestRegisterCertRenewal_MissingNodeID(t *testing.T) {
	err := RegisterCertRenewal(context.Background(), CertRenewalRegistration{
		Scheduler: newFakeScheduler(),
		Registry:  NewCertTargetRegistry(),
	})
	if !errors.Is(err, ErrCertRenewalMissingNodeID) {
		t.Errorf("err = %v, want ErrCertRenewalMissingNodeID", err)
	}
}

// --- RegisterCertRenewal: happy path + idempotency ---

func TestRegisterCertRenewal_HappyPath(t *testing.T) {
	sched := newFakeScheduler()
	reg := NewCertTargetRegistry()
	err := RegisterCertRenewal(context.Background(), CertRenewalRegistration{
		Scheduler: sched,
		Registry:  reg,
		NodeID:    "node-A",
	})
	if err != nil {
		t.Fatalf("RegisterCertRenewal: %v", err)
	}
	if sched.registerCalls != 1 {
		t.Errorf("registerCalls = %d, want 1", sched.registerCalls)
	}
	if sched.scheduleCalls != 1 {
		t.Errorf("scheduleCalls = %d, want 1", sched.scheduleCalls)
	}
	if len(sched.jobs) != 1 {
		t.Fatalf("jobs len = %d", len(sched.jobs))
	}
	job := sched.jobs[0]
	if job.Name != "platform.cert-renewal.node-A" {
		t.Errorf("job.Name = %q", job.Name)
	}
	if job.NodeAffinity != "node-A" {
		t.Errorf("NodeAffinity = %q", job.NodeAffinity)
	}
	if job.Handler != CertRenewalHandlerName {
		t.Errorf("Handler = %q", job.Handler)
	}
	if job.Type != scheduler.JobTypeRecurring {
		t.Errorf("Type = %v, want Recurring", job.Type)
	}
	if job.Schedule != DefaultCertRenewalSchedule {
		t.Errorf("Schedule = %q, want default", job.Schedule)
	}
	if job.Timeout != DefaultCertRenewalTimeout {
		t.Errorf("Timeout = %v", job.Timeout)
	}
	if job.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", job.MaxRetries)
	}
}

func TestRegisterCertRenewal_IdempotentBoot(t *testing.T) {
	sched := newFakeScheduler()
	reg := NewCertTargetRegistry()
	opts := CertRenewalRegistration{
		Scheduler: sched, Registry: reg, NodeID: "node-A",
	}
	if err := RegisterCertRenewal(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	// Second call should NOT create a duplicate job.
	if err := RegisterCertRenewal(context.Background(), opts); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if len(sched.jobs) != 1 {
		t.Errorf("jobs len after idempotent re-boot = %d, want 1", len(sched.jobs))
	}
	// Handler register may also be retried; the fake returns
	// "already registered" which RegisterCertRenewal must tolerate.
	if sched.registerCalls != 2 {
		t.Errorf("registerCalls = %d, want 2 (boot run twice)", sched.registerCalls)
	}
}

func TestRegisterCertRenewal_HandlerRegisterErrorPropagates(t *testing.T) {
	sched := newFakeScheduler()
	sched.registerErr = errors.New("internal scheduler failure")
	err := RegisterCertRenewal(context.Background(), CertRenewalRegistration{
		Scheduler: sched, Registry: NewCertTargetRegistry(), NodeID: "n",
	})
	var want ErrCertRenewalRegisterHandler
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrCertRenewalRegisterHandler", err)
	}
}

func TestRegisterCertRenewal_AlreadyRegisteredTolerated(t *testing.T) {
	sched := newFakeScheduler()
	// Pre-register the handler; second call returns "already registered"
	// which RegisterCertRenewal must accept silently.
	_ = sched.RegisterHandler(CertRenewalHandlerName, func(context.Context, *scheduler.Job) (*scheduler.JobResult, error) {
		return nil, nil
	})
	err := RegisterCertRenewal(context.Background(), CertRenewalRegistration{
		Scheduler: sched, Registry: NewCertTargetRegistry(), NodeID: "n",
	})
	if err != nil {
		t.Errorf("expected nil for already-registered handler tolerance, got %v", err)
	}
}

func TestRegisterCertRenewal_ListJobsError(t *testing.T) {
	sched := newFakeScheduler()
	sched.listErr = errors.New("storage flap")
	err := RegisterCertRenewal(context.Background(), CertRenewalRegistration{
		Scheduler: sched, Registry: NewCertTargetRegistry(), NodeID: "n",
	})
	var want ErrCertRenewalListJobs
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrCertRenewalListJobs", err)
	}
}

func TestRegisterCertRenewal_ScheduleJobError(t *testing.T) {
	sched := newFakeScheduler()
	sched.scheduleErr = errors.New("schedule rejected")
	err := RegisterCertRenewal(context.Background(), CertRenewalRegistration{
		Scheduler: sched, Registry: NewCertTargetRegistry(), NodeID: "n",
	})
	var want ErrCertRenewalScheduleJob
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrCertRenewalScheduleJob", err)
	}
}

func TestRegisterCertRenewal_OverridesRespected(t *testing.T) {
	sched := newFakeScheduler()
	if err := RegisterCertRenewal(context.Background(), CertRenewalRegistration{
		Scheduler:  sched,
		Registry:   NewCertTargetRegistry(),
		NodeID:     "n",
		Schedule:   "*/5 * * * *",
		Threshold:  10 * 24 * time.Hour,
		Timeout:    1 * time.Hour,
		MaxRetries: 7,
	}); err != nil {
		t.Fatal(err)
	}
	job := sched.jobs[0]
	if job.Schedule != "*/5 * * * *" {
		t.Errorf("Schedule override not applied: %q", job.Schedule)
	}
	if job.Timeout != time.Hour {
		t.Errorf("Timeout override not applied: %v", job.Timeout)
	}
	if job.MaxRetries != 7 {
		t.Errorf("MaxRetries override not applied: %d", job.MaxRetries)
	}
}

// --- runCertRenewalSweep ---

func TestRunSweep_EmptyRegistry(t *testing.T) {
	r := NewCertTargetRegistry()
	got := runCertRenewalSweep(context.Background(), r, time.Hour, time.Now(), nil)
	if got != nil {
		t.Errorf("expected nil for empty registry, got %v", got)
	}
}

func TestRunSweep_NilRegistry(t *testing.T) {
	got := runCertRenewalSweep(context.Background(), nil, time.Hour, time.Now(), nil)
	if got != nil {
		t.Errorf("expected nil for nil registry, got %v", got)
	}
}

func TestRunSweep_SkipsNotDue(t *testing.T) {
	r := NewCertTargetRegistry()
	now := time.Now()
	st := &stubTarget{name: "bmc.x", notAfter: now.Add(60 * 24 * time.Hour)}
	_ = r.Register(st.buildTarget())

	got := runCertRenewalSweep(context.Background(), r, 30*24*time.Hour, now, nil)
	if len(got) != 1 {
		t.Fatalf("got %d results", len(got))
	}
	if got[0].Action != "skipped" {
		t.Errorf("Action = %q, want skipped", got[0].Action)
	}
	if st.reissueCalls != 0 {
		t.Errorf("reissueCalls = %d, want 0", st.reissueCalls)
	}
}

func TestRunSweep_RenewsDue(t *testing.T) {
	r := NewCertTargetRegistry()
	now := time.Now()
	st := &stubTarget{name: "bmc.x", notAfter: now.Add(7 * 24 * time.Hour)}
	_ = r.Register(st.buildTarget())

	got := runCertRenewalSweep(context.Background(), r, 30*24*time.Hour, now, nil)
	if got[0].Action != "renewed" {
		t.Errorf("Action = %q, want renewed", got[0].Action)
	}
	if st.reissueCalls != 1 {
		t.Errorf("reissueCalls = %d, want 1", st.reissueCalls)
	}
}

func TestRunSweep_ReissueErrorRecorded(t *testing.T) {
	r := NewCertTargetRegistry()
	now := time.Now()
	st := &stubTarget{
		name:       "bmc.x",
		notAfter:   now.Add(7 * 24 * time.Hour),
		reissueErr: errors.New("ACME rate limit"),
	}
	_ = r.Register(st.buildTarget())

	got := runCertRenewalSweep(context.Background(), r, 30*24*time.Hour, now, nil)
	if got[0].Action != "failed" {
		t.Errorf("Action = %q, want failed", got[0].Action)
	}
	if !strings.Contains(got[0].Error, "ACME rate limit") {
		t.Errorf("Error = %q", got[0].Error)
	}
}

func TestRunSweep_CurrentErrorRecorded(t *testing.T) {
	r := NewCertTargetRegistry()
	now := time.Now()
	st := &stubTarget{name: "bmc.x", currentErr: errors.New("dial failed")}
	_ = r.Register(st.buildTarget())

	got := runCertRenewalSweep(context.Background(), r, 30*24*time.Hour, now, nil)
	if got[0].Action != "failed" {
		t.Errorf("Action = %q, want failed", got[0].Action)
	}
	if !strings.Contains(got[0].Error, "dial failed") {
		t.Errorf("Error = %q", got[0].Error)
	}
}

func TestRunSweep_NilCertRecorded(t *testing.T) {
	r := NewCertTargetRegistry()
	st := &stubTarget{name: "bmc.x", currentNil: true}
	_ = r.Register(st.buildTarget())
	got := runCertRenewalSweep(context.Background(), r, time.Hour, time.Now(), nil)
	if got[0].Action != "failed" {
		t.Errorf("Action = %q", got[0].Action)
	}
	if !strings.Contains(got[0].Error, "nil certificate") {
		t.Errorf("Error = %q", got[0].Error)
	}
}

func TestRunSweep_PartialFailureContinues(t *testing.T) {
	r := NewCertTargetRegistry()
	now := time.Now()
	due := &stubTarget{name: "a.due", notAfter: now.Add(5 * 24 * time.Hour), reissueErr: errors.New("boom")}
	skip := &stubTarget{name: "b.skip", notAfter: now.Add(60 * 24 * time.Hour)}
	ok := &stubTarget{name: "c.ok", notAfter: now.Add(5 * 24 * time.Hour)}
	for _, s := range []*stubTarget{due, skip, ok} {
		_ = r.Register(s.buildTarget())
	}

	got := runCertRenewalSweep(context.Background(), r, 30*24*time.Hour, now, nil)
	if len(got) != 3 {
		t.Fatalf("len = %d", len(got))
	}
	// Sorted by name.
	if got[0].Action != "failed" {
		t.Errorf("a.due action = %q, want failed", got[0].Action)
	}
	if got[1].Action != "skipped" {
		t.Errorf("b.skip action = %q, want skipped", got[1].Action)
	}
	if got[2].Action != "renewed" {
		t.Errorf("c.ok action = %q, want renewed", got[2].Action)
	}
	// Subsequent targets must still have been processed.
	if ok.reissueCalls != 1 {
		t.Error("c.ok was not reissued despite a.due failing")
	}
}

// --- handler integration ---

func TestBuildHandler_OK(t *testing.T) {
	r := NewCertTargetRegistry()
	now := time.Now()
	due := &stubTarget{name: "x", notAfter: now.Add(5 * 24 * time.Hour)}
	_ = r.Register(due.buildTarget())

	h := buildCertRenewalHandler(r, 30*24*time.Hour, nil)
	res, err := h(context.Background(), &scheduler.Job{Name: "j"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !res.Success {
		t.Errorf("Success = false, message=%q", res.Message)
	}
	if !strings.Contains(res.Message, "1 renewed") {
		t.Errorf("message = %q", res.Message)
	}
	// Payload is JSON-decoded list of results.
	var payload []renewalResult
	if err := json.Unmarshal(res.Output, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if len(payload) != 1 || payload[0].Action != "renewed" {
		t.Errorf("payload unexpected: %+v", payload)
	}
}

func TestBuildHandler_FailureSurfacedAsSuccessFalse(t *testing.T) {
	r := NewCertTargetRegistry()
	now := time.Now()
	bad := &stubTarget{
		name:       "x",
		notAfter:   now.Add(5 * 24 * time.Hour),
		reissueErr: errors.New("nope"),
	}
	_ = r.Register(bad.buildTarget())
	h := buildCertRenewalHandler(r, 30*24*time.Hour, nil)
	res, err := h(context.Background(), &scheduler.Job{})
	if err != nil {
		t.Fatalf("handler returned err: %v", err)
	}
	if res.Success {
		t.Error("Success should be false when any target failed")
	}
}

func TestBuildHandler_EmptyRegistryBenign(t *testing.T) {
	r := NewCertTargetRegistry()
	h := buildCertRenewalHandler(r, time.Hour, nil)
	res, err := h(context.Background(), &scheduler.Job{})
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if !res.Success {
		t.Error("empty registry should produce Success=true")
	}
	if !strings.Contains(res.Message, "no cert targets") {
		t.Errorf("message = %q", res.Message)
	}
}

// --- helpers ---

func TestRenewalJobName(t *testing.T) {
	if got := renewalJobName("nodeX"); got != "platform.cert-renewal.nodeX" {
		t.Errorf("renewalJobName = %q", got)
	}
}

func TestIsAlreadyRegistered(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("handler already registered: foo"), true},
		{errors.New("Already Registered"), true},
		{errors.New("duplicate handler name"), true},
		{errors.New("permission denied"), false},
	}
	for _, tc := range cases {
		if got := isAlreadyRegistered(tc.err); got != tc.want {
			t.Errorf("isAlreadyRegistered(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestSummarizeResults(t *testing.T) {
	results := []renewalResult{
		{Action: "renewed"}, {Action: "renewed"},
		{Action: "skipped"},
		{Action: "failed"},
	}
	s := summarizeResults(results)
	if !strings.Contains(s, "2 renewed") || !strings.Contains(s, "1 skipped") || !strings.Contains(s, "1 failed") {
		t.Errorf("summary = %q", s)
	}
	if !strings.Contains(s, "of 4 targets") {
		t.Errorf("summary missing total count: %q", s)
	}
	if got := summarizeResults(nil); !strings.Contains(got, "no cert targets") {
		t.Errorf("nil summary = %q", got)
	}
}

// --- error message coverage ---

func TestCertRenewalErrorMessages(t *testing.T) {
	cases := []error{
		ErrCertRenewalMissingScheduler,
		ErrCertRenewalMissingRegistry,
		ErrCertRenewalMissingNodeID,
		ErrCertRenewalRegisterHandler{Cause: errors.New("c")},
		ErrCertRenewalListJobs{Cause: errors.New("c")},
		ErrCertRenewalScheduleJob{Cause: errors.New("c")},
	}
	for _, e := range cases {
		if e.Error() == "" {
			t.Errorf("empty error from %T", e)
		}
	}
	inner := errors.New("inner")
	wrapped := []error{
		ErrCertRenewalRegisterHandler{Cause: inner},
		ErrCertRenewalListJobs{Cause: inner},
		ErrCertRenewalScheduleJob{Cause: inner},
	}
	for _, e := range wrapped {
		if !errors.Is(e, inner) {
			t.Errorf("%T does not unwrap", e)
		}
	}
}
