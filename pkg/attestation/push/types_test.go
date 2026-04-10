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

package push

import (
	"testing"
	"time"
)

func TestTransportType(t *testing.T) {
	t.Run("String", func(t *testing.T) {
		if TransportHTTP.String() != "http" {
			t.Error("expected http")
		}
		if TransportGRPC.String() != "grpc" {
			t.Error("expected grpc")
		}
	})

	t.Run("IsValid", func(t *testing.T) {
		validTransports := []TransportType{TransportHTTP, TransportGRPC}
		for _, tr := range validTransports {
			if !tr.IsValid() {
				t.Errorf("expected %s to be valid", tr)
			}
		}

		invalidTransport := TransportType("websocket")
		if invalidTransport.IsValid() {
			t.Error("expected websocket to be invalid")
		}
	})
}

func TestTriggerType(t *testing.T) {
	t.Run("String", func(t *testing.T) {
		if TriggerPeriodic.String() != "periodic" {
			t.Error("expected periodic")
		}
		if TriggerOnChange.String() != "on-change" {
			t.Error("expected on-change")
		}
		if TriggerManual.String() != "manual" {
			t.Error("expected manual")
		}
	})

	t.Run("IsValid", func(t *testing.T) {
		validTriggers := []TriggerType{TriggerPeriodic, TriggerOnChange, TriggerManual}
		for _, tr := range validTriggers {
			if !tr.IsValid() {
				t.Errorf("expected %s to be valid", tr)
			}
		}

		invalidTrigger := TriggerType("random")
		if invalidTrigger.IsValid() {
			t.Error("expected random to be invalid")
		}
	})
}

func TestPushStatus(t *testing.T) {
	t.Run("String", func(t *testing.T) {
		if PushStatusPending.String() != "pending" {
			t.Error("expected pending")
		}
		if PushStatusSuccess.String() != "success" {
			t.Error("expected success")
		}
	})

	t.Run("IsValid", func(t *testing.T) {
		validStatuses := []PushStatus{
			PushStatusPending, PushStatusInFlight, PushStatusSuccess,
			PushStatusFailed, PushStatusRetrying, PushStatusCanceled, PushStatusSkipped,
		}
		for _, s := range validStatuses {
			if !s.IsValid() {
				t.Errorf("expected %s to be valid", s)
			}
		}

		invalidStatus := PushStatus("unknown")
		if invalidStatus.IsValid() {
			t.Error("expected unknown to be invalid")
		}
	})

	t.Run("IsTerminal", func(t *testing.T) {
		terminalStatuses := []PushStatus{
			PushStatusSuccess, PushStatusFailed, PushStatusCanceled, PushStatusSkipped,
		}
		for _, s := range terminalStatuses {
			if !s.IsTerminal() {
				t.Errorf("expected %s to be terminal", s)
			}
		}

		nonTerminalStatuses := []PushStatus{
			PushStatusPending, PushStatusInFlight, PushStatusRetrying,
		}
		for _, s := range nonTerminalStatuses {
			if s.IsTerminal() {
				t.Errorf("expected %s to be non-terminal", s)
			}
		}
	})
}

func TestAuthConfig(t *testing.T) {
	t.Run("Validate empty auth", func(t *testing.T) {
		auth := &AuthConfig{}
		if err := auth.Validate(); err != nil {
			t.Errorf("empty auth should be valid: %v", err)
		}
	})

	t.Run("Validate bearer auth", func(t *testing.T) {
		auth := &AuthConfig{Type: "bearer", Token: "my-token"}
		if err := auth.Validate(); err != nil {
			t.Errorf("valid bearer auth should pass: %v", err)
		}

		auth = &AuthConfig{Type: "bearer"}
		if err := auth.Validate(); err == nil {
			t.Error("bearer auth without token should fail")
		}
	})

	t.Run("Validate basic auth", func(t *testing.T) {
		auth := &AuthConfig{Type: "basic", Username: "user", Password: "pass"}
		if err := auth.Validate(); err != nil {
			t.Errorf("valid basic auth should pass: %v", err)
		}

		auth = &AuthConfig{Type: "basic"}
		if err := auth.Validate(); err == nil {
			t.Error("basic auth without username should fail")
		}
	})

	t.Run("Validate mTLS auth", func(t *testing.T) {
		auth := &AuthConfig{Type: "mtls", ClientCert: "/path/cert.pem", ClientKey: "/path/key.pem"}
		if err := auth.Validate(); err != nil {
			t.Errorf("valid mtls auth should pass: %v", err)
		}

		auth = &AuthConfig{Type: "mtls", ClientCert: "/path/cert.pem"}
		if err := auth.Validate(); err == nil {
			t.Error("mtls auth without key should fail")
		}

		auth = &AuthConfig{Type: "mtls", ClientKey: "/path/key.pem"}
		if err := auth.Validate(); err == nil {
			t.Error("mtls auth without cert should fail")
		}
	})

	t.Run("Validate unsupported auth type", func(t *testing.T) {
		auth := &AuthConfig{Type: "oauth2"}
		if err := auth.Validate(); err == nil {
			t.Error("unsupported auth type should fail")
		}
	})
}

func TestPushTarget(t *testing.T) {
	t.Run("Validate valid target", func(t *testing.T) {
		target := &PushTarget{
			ID:        "target-1",
			Name:      "Test Target",
			Endpoint:  "https://api.example.com/push",
			Transport: TransportHTTP,
			Enabled:   true,
			Timeout:   30 * time.Second,
		}
		if err := target.Validate(); err != nil {
			t.Errorf("valid target should pass: %v", err)
		}
	})

	t.Run("Validate missing ID", func(t *testing.T) {
		target := &PushTarget{
			Endpoint:  "https://api.example.com/push",
			Transport: TransportHTTP,
		}
		if err := target.Validate(); err == nil {
			t.Error("target without ID should fail")
		}
	})

	t.Run("Validate missing endpoint", func(t *testing.T) {
		target := &PushTarget{
			ID:        "target-1",
			Transport: TransportHTTP,
		}
		if err := target.Validate(); err == nil {
			t.Error("target without endpoint should fail")
		}
	})

	t.Run("Validate invalid endpoint", func(t *testing.T) {
		target := &PushTarget{
			ID:        "target-1",
			Endpoint:  "://invalid",
			Transport: TransportHTTP,
		}
		if err := target.Validate(); err == nil {
			t.Error("target with invalid endpoint should fail")
		}
	})

	t.Run("Validate endpoint without host", func(t *testing.T) {
		target := &PushTarget{
			ID:        "target-1",
			Endpoint:  "/path/only",
			Transport: TransportHTTP,
		}
		if err := target.Validate(); err == nil {
			t.Error("target without host should fail")
		}
	})

	t.Run("Validate invalid transport", func(t *testing.T) {
		target := &PushTarget{
			ID:        "target-1",
			Endpoint:  "https://api.example.com/push",
			Transport: TransportType("invalid"),
		}
		if err := target.Validate(); err == nil {
			t.Error("target with invalid transport should fail")
		}
	})

	t.Run("Validate negative timeout", func(t *testing.T) {
		target := &PushTarget{
			ID:        "target-1",
			Endpoint:  "https://api.example.com/push",
			Transport: TransportHTTP,
			Timeout:   -1 * time.Second,
		}
		if err := target.Validate(); err == nil {
			t.Error("target with negative timeout should fail")
		}
	})

	t.Run("Validate with invalid auth", func(t *testing.T) {
		target := &PushTarget{
			ID:        "target-1",
			Endpoint:  "https://api.example.com/push",
			Transport: TransportHTTP,
			Auth:      &AuthConfig{Type: "bearer"}, // Missing token
		}
		if err := target.Validate(); err == nil {
			t.Error("target with invalid auth should fail")
		}
	})
}

func TestPushResult(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		result := &PushResult{Status: PushStatusSuccess}
		if !result.Success() {
			t.Error("expected Success() to return true")
		}

		result.Status = PushStatusFailed
		if result.Success() {
			t.Error("expected Success() to return false")
		}
	})
}

func TestRetryConfig(t *testing.T) {
	t.Run("Validate valid config", func(t *testing.T) {
		cfg := DefaultRetryConfig()
		if err := cfg.Validate(); err != nil {
			t.Errorf("default config should be valid: %v", err)
		}
	})

	t.Run("Validate MaxAttempts", func(t *testing.T) {
		cfg := &RetryConfig{
			MaxAttempts:       0,
			InitialBackoff:    100 * time.Millisecond,
			MaxBackoff:        10 * time.Second,
			BackoffMultiplier: 2.0,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("zero MaxAttempts should fail")
		}
	})

	t.Run("Validate InitialBackoff", func(t *testing.T) {
		cfg := &RetryConfig{
			MaxAttempts:       3,
			InitialBackoff:    0,
			MaxBackoff:        10 * time.Second,
			BackoffMultiplier: 2.0,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("zero InitialBackoff should fail")
		}
	})

	t.Run("Validate MaxBackoff", func(t *testing.T) {
		cfg := &RetryConfig{
			MaxAttempts:       3,
			InitialBackoff:    10 * time.Second,
			MaxBackoff:        1 * time.Second,
			BackoffMultiplier: 2.0,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("MaxBackoff < InitialBackoff should fail")
		}
	})

	t.Run("Validate BackoffMultiplier", func(t *testing.T) {
		cfg := &RetryConfig{
			MaxAttempts:       3,
			InitialBackoff:    100 * time.Millisecond,
			MaxBackoff:        10 * time.Second,
			BackoffMultiplier: 0.5,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("BackoffMultiplier < 1.0 should fail")
		}
	})

	t.Run("IsRetryableStatus", func(t *testing.T) {
		cfg := DefaultRetryConfig()

		retryable := []int{408, 429, 500, 502, 503, 504}
		for _, code := range retryable {
			if !cfg.IsRetryableStatus(code) {
				t.Errorf("status %d should be retryable", code)
			}
		}

		nonRetryable := []int{200, 201, 400, 401, 403, 404}
		for _, code := range nonRetryable {
			if cfg.IsRetryableStatus(code) {
				t.Errorf("status %d should not be retryable", code)
			}
		}
	})

	t.Run("CalculateBackoff", func(t *testing.T) {
		cfg := &RetryConfig{
			MaxAttempts:       5,
			InitialBackoff:    100 * time.Millisecond,
			MaxBackoff:        1 * time.Second,
			BackoffMultiplier: 2.0,
		}

		// First attempt (0 or 1) should return initial backoff
		if cfg.CalculateBackoff(0) != 100*time.Millisecond {
			t.Error("attempt 0 should return initial backoff")
		}
		if cfg.CalculateBackoff(1) != 100*time.Millisecond {
			t.Error("attempt 1 should return initial backoff")
		}

		// Second attempt: 100ms * 2 = 200ms
		if cfg.CalculateBackoff(2) != 200*time.Millisecond {
			t.Errorf("attempt 2 should return 200ms, got %v", cfg.CalculateBackoff(2))
		}

		// Third attempt: 200ms * 2 = 400ms
		if cfg.CalculateBackoff(3) != 400*time.Millisecond {
			t.Errorf("attempt 3 should return 400ms, got %v", cfg.CalculateBackoff(3))
		}

		// Should cap at MaxBackoff
		if cfg.CalculateBackoff(10) != 1*time.Second {
			t.Errorf("high attempt should return max backoff, got %v", cfg.CalculateBackoff(10))
		}
	})
}

func TestPushConfig(t *testing.T) {
	t.Run("Validate valid config", func(t *testing.T) {
		cfg := &PushConfig{
			Targets: []*PushTarget{
				{
					ID:        "target-1",
					Endpoint:  "https://api.example.com",
					Transport: TransportHTTP,
				},
			},
			Retry:               DefaultRetryConfig(),
			DefaultTimeout:      30 * time.Second,
			DefaultTransport:    TransportHTTP,
			TriggerType:         TriggerPeriodic,
			PushInterval:        5 * time.Minute,
			MaxConcurrentPushes: 10,
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("valid config should pass: %v", err)
		}
	})

	t.Run("Validate no targets", func(t *testing.T) {
		cfg := &PushConfig{
			Targets: []*PushTarget{},
		}
		if err := cfg.Validate(); err == nil {
			t.Error("config with no targets should fail")
		}
	})

	t.Run("Validate invalid target", func(t *testing.T) {
		cfg := &PushConfig{
			Targets: []*PushTarget{
				{ID: ""}, // Invalid
			},
		}
		if err := cfg.Validate(); err == nil {
			t.Error("config with invalid target should fail")
		}
	})

	t.Run("Validate negative timeout", func(t *testing.T) {
		cfg := &PushConfig{
			Targets: []*PushTarget{
				{
					ID:        "target-1",
					Endpoint:  "https://api.example.com",
					Transport: TransportHTTP,
				},
			},
			DefaultTimeout: -1 * time.Second,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("config with negative timeout should fail")
		}
	})

	t.Run("Validate invalid transport", func(t *testing.T) {
		cfg := &PushConfig{
			Targets: []*PushTarget{
				{
					ID:        "target-1",
					Endpoint:  "https://api.example.com",
					Transport: TransportHTTP,
				},
			},
			DefaultTransport: TransportType("invalid"),
		}
		if err := cfg.Validate(); err == nil {
			t.Error("config with invalid transport should fail")
		}
	})

	t.Run("Validate invalid trigger", func(t *testing.T) {
		cfg := &PushConfig{
			Targets: []*PushTarget{
				{
					ID:        "target-1",
					Endpoint:  "https://api.example.com",
					Transport: TransportHTTP,
				},
			},
			TriggerType: TriggerType("invalid"),
		}
		if err := cfg.Validate(); err == nil {
			t.Error("config with invalid trigger should fail")
		}
	})

	t.Run("Validate periodic without interval", func(t *testing.T) {
		cfg := &PushConfig{
			Targets: []*PushTarget{
				{
					ID:        "target-1",
					Endpoint:  "https://api.example.com",
					Transport: TransportHTTP,
				},
			},
			TriggerType:  TriggerPeriodic,
			PushInterval: 0,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("periodic trigger without interval should fail")
		}
	})

	t.Run("Validate negative concurrent pushes", func(t *testing.T) {
		cfg := &PushConfig{
			Targets: []*PushTarget{
				{
					ID:        "target-1",
					Endpoint:  "https://api.example.com",
					Transport: TransportHTTP,
				},
			},
			MaxConcurrentPushes: -1,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("config with negative concurrent pushes should fail")
		}
	})

	t.Run("GetEnabledTargets", func(t *testing.T) {
		cfg := &PushConfig{
			Targets: []*PushTarget{
				{ID: "t1", Endpoint: "https://a.com", Transport: TransportHTTP, Enabled: true},
				{ID: "t2", Endpoint: "https://b.com", Transport: TransportHTTP, Enabled: false},
				{ID: "t3", Endpoint: "https://c.com", Transport: TransportHTTP, Enabled: true},
			},
		}

		enabled := cfg.GetEnabledTargets()
		if len(enabled) != 2 {
			t.Errorf("expected 2 enabled targets, got %d", len(enabled))
		}
	})

	t.Run("GetTargetByID", func(t *testing.T) {
		cfg := &PushConfig{
			Targets: []*PushTarget{
				{ID: "t1", Endpoint: "https://a.com", Transport: TransportHTTP},
				{ID: "t2", Endpoint: "https://b.com", Transport: TransportHTTP},
			},
		}

		target := cfg.GetTargetByID("t2")
		if target == nil {
			t.Fatal("expected to find target t2")
		}
		if target.ID != "t2" {
			t.Errorf("expected t2, got %s", target.ID)
		}

		target = cfg.GetTargetByID("missing")
		if target != nil {
			t.Error("expected nil for missing target")
		}
	})
}

func TestClientConfig(t *testing.T) {
	t.Run("Validate valid config", func(t *testing.T) {
		cfg := DefaultClientConfig()
		if err := cfg.Validate(); err != nil {
			t.Errorf("default config should be valid: %v", err)
		}
	})

	t.Run("Validate negative timeout", func(t *testing.T) {
		cfg := &ClientConfig{DefaultTimeout: -1}
		if err := cfg.Validate(); err == nil {
			t.Error("negative timeout should fail")
		}
	})

	t.Run("Validate negative idle conns", func(t *testing.T) {
		cfg := &ClientConfig{MaxIdleConns: -1}
		if err := cfg.Validate(); err == nil {
			t.Error("negative max idle conns should fail")
		}
	})

	t.Run("Validate negative idle conns per host", func(t *testing.T) {
		cfg := &ClientConfig{MaxIdleConnsPerHost: -1}
		if err := cfg.Validate(); err == nil {
			t.Error("negative max idle conns per host should fail")
		}
	})

	t.Run("Validate negative idle conn timeout", func(t *testing.T) {
		cfg := &ClientConfig{IdleConnTimeout: -1}
		if err := cfg.Validate(); err == nil {
			t.Error("negative idle conn timeout should fail")
		}
	})
}

func TestSchedulerConfig(t *testing.T) {
	t.Run("Validate valid config", func(t *testing.T) {
		cfg := DefaultSchedulerConfig()
		if err := cfg.Validate(); err != nil {
			t.Errorf("default config should be valid: %v", err)
		}
	})

	t.Run("Validate invalid trigger type", func(t *testing.T) {
		cfg := &SchedulerConfig{
			TriggerType:         TriggerType("invalid"),
			MaxConcurrentPushes: 1,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("invalid trigger type should fail")
		}
	})

	t.Run("Validate periodic without interval", func(t *testing.T) {
		cfg := &SchedulerConfig{
			TriggerType:         TriggerPeriodic,
			PushInterval:        0,
			MaxConcurrentPushes: 1,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("periodic without interval should fail")
		}
	})

	t.Run("Validate zero concurrent pushes", func(t *testing.T) {
		cfg := &SchedulerConfig{
			TriggerType:         TriggerManual,
			MaxConcurrentPushes: 0,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("zero concurrent pushes should fail")
		}
	})

	t.Run("Validate negative debounce", func(t *testing.T) {
		cfg := &SchedulerConfig{
			TriggerType:         TriggerOnChange,
			MaxConcurrentPushes: 1,
			OnChangeDebounce:    -1 * time.Second,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("negative debounce should fail")
		}
	})
}

func TestPushRequest(t *testing.T) {
	t.Run("Validate valid request", func(t *testing.T) {
		req := &PushRequest{
			ManifestID:  "manifest-1",
			Payload:     []byte(`{"test": "data"}`),
			ContentType: "application/json",
		}
		if err := req.Validate(); err != nil {
			t.Errorf("valid request should pass: %v", err)
		}
	})

	t.Run("Validate empty payload", func(t *testing.T) {
		req := &PushRequest{
			ContentType: "application/json",
		}
		if err := req.Validate(); err == nil {
			t.Error("empty payload should fail")
		}
	})

	t.Run("Validate empty content type", func(t *testing.T) {
		req := &PushRequest{
			Payload: []byte(`{"test": "data"}`),
		}
		if err := req.Validate(); err == nil {
			t.Error("empty content type should fail")
		}
	})
}

func TestPushBatchResult(t *testing.T) {
	t.Run("AllSuccess", func(t *testing.T) {
		result := &PushBatchResult{
			SuccessCount: 3,
			FailureCount: 0,
		}
		if !result.AllSuccess() {
			t.Error("expected AllSuccess to return true")
		}

		result.FailureCount = 1
		if result.AllSuccess() {
			t.Error("expected AllSuccess to return false with failures")
		}

		result = &PushBatchResult{
			SuccessCount: 0,
			FailureCount: 0,
		}
		if result.AllSuccess() {
			t.Error("expected AllSuccess to return false with no successes")
		}
	})

	t.Run("AnySuccess", func(t *testing.T) {
		result := &PushBatchResult{
			SuccessCount: 1,
			FailureCount: 2,
		}
		if !result.AnySuccess() {
			t.Error("expected AnySuccess to return true")
		}

		result.SuccessCount = 0
		if result.AnySuccess() {
			t.Error("expected AnySuccess to return false")
		}
	})

	t.Run("GetFailedResults", func(t *testing.T) {
		result := &PushBatchResult{
			Results: []*PushResult{
				{TargetID: "t1", Status: PushStatusSuccess},
				{TargetID: "t2", Status: PushStatusFailed},
				{TargetID: "t3", Status: PushStatusSuccess},
				{TargetID: "t4", Status: PushStatusFailed},
			},
			FailureCount: 2,
		}

		failed := result.GetFailedResults()
		if len(failed) != 2 {
			t.Errorf("expected 2 failed results, got %d", len(failed))
		}
		for _, r := range failed {
			if r.Status != PushStatusFailed {
				t.Error("GetFailedResults returned non-failed result")
			}
		}
	})

	t.Run("GetSuccessResults", func(t *testing.T) {
		result := &PushBatchResult{
			Results: []*PushResult{
				{TargetID: "t1", Status: PushStatusSuccess},
				{TargetID: "t2", Status: PushStatusFailed},
				{TargetID: "t3", Status: PushStatusSuccess},
			},
			SuccessCount: 2,
		}

		successful := result.GetSuccessResults()
		if len(successful) != 2 {
			t.Errorf("expected 2 successful results, got %d", len(successful))
		}
		for _, r := range successful {
			if r.Status != PushStatusSuccess {
				t.Error("GetSuccessResults returned non-success result")
			}
		}
	})
}

func TestDefaultConfigs(t *testing.T) {
	t.Run("DefaultRetryConfig", func(t *testing.T) {
		cfg := DefaultRetryConfig()
		if cfg.MaxAttempts != 3 {
			t.Errorf("expected MaxAttempts 3, got %d", cfg.MaxAttempts)
		}
		if cfg.InitialBackoff != 100*time.Millisecond {
			t.Errorf("expected InitialBackoff 100ms, got %v", cfg.InitialBackoff)
		}
		if cfg.MaxBackoff != 10*time.Second {
			t.Errorf("expected MaxBackoff 10s, got %v", cfg.MaxBackoff)
		}
		if cfg.BackoffMultiplier != 2.0 {
			t.Errorf("expected BackoffMultiplier 2.0, got %f", cfg.BackoffMultiplier)
		}
		if len(cfg.RetryableStatusCodes) != 6 {
			t.Errorf("expected 6 retryable status codes, got %d", len(cfg.RetryableStatusCodes))
		}
	})

	t.Run("DefaultPushConfig", func(t *testing.T) {
		cfg := DefaultPushConfig()
		if cfg.DefaultTimeout != 30*time.Second {
			t.Errorf("expected DefaultTimeout 30s, got %v", cfg.DefaultTimeout)
		}
		if cfg.DefaultTransport != TransportHTTP {
			t.Errorf("expected DefaultTransport HTTP, got %v", cfg.DefaultTransport)
		}
		if cfg.TriggerType != TriggerPeriodic {
			t.Errorf("expected TriggerType Periodic, got %v", cfg.TriggerType)
		}
		if cfg.PushInterval != 5*time.Minute {
			t.Errorf("expected PushInterval 5m, got %v", cfg.PushInterval)
		}
		if cfg.MaxConcurrentPushes != 10 {
			t.Errorf("expected MaxConcurrentPushes 10, got %d", cfg.MaxConcurrentPushes)
		}
	})

	t.Run("DefaultClientConfig", func(t *testing.T) {
		cfg := DefaultClientConfig()
		if cfg.DefaultTimeout != 30*time.Second {
			t.Errorf("expected DefaultTimeout 30s, got %v", cfg.DefaultTimeout)
		}
		if cfg.UserAgent != "go-trusted-platform/1.0" {
			t.Errorf("unexpected UserAgent: %s", cfg.UserAgent)
		}
		if cfg.MaxIdleConns != 100 {
			t.Errorf("expected MaxIdleConns 100, got %d", cfg.MaxIdleConns)
		}
		if cfg.MaxIdleConnsPerHost != 10 {
			t.Errorf("expected MaxIdleConnsPerHost 10, got %d", cfg.MaxIdleConnsPerHost)
		}
		if cfg.IdleConnTimeout != 90*time.Second {
			t.Errorf("expected IdleConnTimeout 90s, got %v", cfg.IdleConnTimeout)
		}
	})

	t.Run("DefaultSchedulerConfig", func(t *testing.T) {
		cfg := DefaultSchedulerConfig()
		if cfg.TriggerType != TriggerPeriodic {
			t.Errorf("expected TriggerType Periodic, got %v", cfg.TriggerType)
		}
		if cfg.PushInterval != 5*time.Minute {
			t.Errorf("expected PushInterval 5m, got %v", cfg.PushInterval)
		}
		if cfg.MaxConcurrentPushes != 10 {
			t.Errorf("expected MaxConcurrentPushes 10, got %d", cfg.MaxConcurrentPushes)
		}
		if cfg.OnChangeDebounce != 1*time.Second {
			t.Errorf("expected OnChangeDebounce 1s, got %v", cfg.OnChangeDebounce)
		}
	})
}
