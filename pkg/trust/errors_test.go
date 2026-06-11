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

package trust

import (
	"errors"
	"strings"
	"testing"
)

func TestErrorMessages(t *testing.T) {
	cause := errors.New("boom")
	tests := []struct {
		name string
		err  error
		want []string
	}{
		{"nil config", ErrNilConfig{}, []string{"config is required"}},
		{"nil logger", ErrNilLogger{}, []string{"logger is required"}},
		{"class not configured", &ErrClassNotConfigured{Class: ClassBMC}, []string{"bmc", "not configured"}},
		{"invalid config", &ErrInvalidConfig{Class: ClassDefault, Field: "strategies", Reason: "empty"}, []string{"default", "strategies", "empty"}},
		{"strategy not allowed", &ErrStrategyNotAllowed{Class: ClassInternal, Strategy: StrategyDANE}, []string{"dane", "internal"}},
		{"fetch failed", &ErrFetchFailed{Strategy: StrategySPKI, Cause: cause}, []string{"spki", "boom"}},
		{"bundle empty", ErrCABundleEmpty{}, []string{"empty"}},
		{"bundle parse", ErrCABundleParse{}, []string{"PEM"}},
		{"write failed", &ErrWriteFailed{Path: "/x/y", Err: cause}, []string{"/x/y", "boom"}},
		// ErrPlatformCAUnavailable is an alias for ErrProviderCAUnavailable;
		// the upstream message contains "provider-ca".
		{"platform ca unavailable", ErrPlatformCAUnavailable{}, []string{"provider-ca"}},
		{"pin not found with endpoint", &ErrPinNotFound{Endpoint: "bmc:443"}, []string{"bmc:443"}},
		{"pin not found without endpoint", &ErrPinNotFound{}, []string{"no SPKI pin"}},
		{"ca file read", &ErrCAFileRead{Path: "/ca.pem", Err: cause}, []string{"/ca.pem", "boom"}},
		{"endpoint invalid", &ErrEndpointInvalid{Endpoint: "x", Reason: "no port"}, []string{"x", "no port"}},
		{"tofu pin store required", ErrTOFUPinStoreRequired{}, []string{"tofu"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, want := range tt.want {
				if !strings.Contains(msg, want) {
					t.Errorf("expected %q in message %q", want, msg)
				}
			}
		})
	}
}

func TestErrorUnwrap(t *testing.T) {
	cause := errors.New("root cause")
	if !errors.Is(&ErrFetchFailed{Strategy: StrategyDANE, Cause: cause}, cause) {
		t.Error("ErrFetchFailed must unwrap to its cause")
	}
	if !errors.Is(&ErrWriteFailed{Path: "/x", Err: cause}, cause) {
		t.Error("ErrWriteFailed must unwrap to its cause")
	}
	if !errors.Is(&ErrCAFileRead{Path: "/x", Err: cause}, cause) {
		t.Error("ErrCAFileRead must unwrap to its cause")
	}
}

func TestErrNoStrategySucceeded(t *testing.T) {
	daneErr := errors.New("dnssec validation failed")
	pinErr := &ErrPinNotFound{Endpoint: "bmc:443"}
	err := &ErrNoStrategySucceeded{
		Class:    ClassBMC,
		Endpoint: "bmc:443",
		Attempts: []Attempt{
			{Strategy: StrategyDANE, Err: daneErr},
			{Strategy: StrategySPKI, Err: pinErr},
		},
	}

	msg := err.Error()
	for _, want := range []string{"bmc", "bmc:443", "dane", "dnssec validation failed", "spki"} {
		if !strings.Contains(msg, want) {
			t.Errorf("expected %q in message %q", want, msg)
		}
	}

	if !errors.Is(err, daneErr) {
		t.Error("expected errors.Is to find the dane attempt error")
	}
	var foundPin *ErrPinNotFound
	if !errors.As(err, &foundPin) {
		t.Error("expected errors.As to find the pin attempt error")
	}
}

func TestErrNoStrategySucceeded_NoEndpoint(t *testing.T) {
	err := &ErrNoStrategySucceeded{Class: ClassDefault}
	msg := err.Error()
	if !strings.Contains(msg, "default") {
		t.Errorf("expected class in message %q", msg)
	}
	if strings.Contains(msg, "endpoint") {
		t.Errorf("expected no endpoint clause in message %q", msg)
	}
	if len(err.Unwrap()) != 0 {
		t.Error("expected empty unwrap list")
	}
}

func TestErrNilConfig_Is(t *testing.T) {
	if !errors.Is(ErrNilConfig{}, ErrNilConfig{}) {
		t.Error("ErrNilConfig must satisfy errors.Is against itself")
	}
}

func TestErrNilLogger_Is(t *testing.T) {
	if !errors.Is(ErrNilLogger{}, ErrNilLogger{}) {
		t.Error("ErrNilLogger must satisfy errors.Is against itself")
	}
}

func TestErrPlatformCAUnavailable_IsErrProviderCAUnavailable(t *testing.T) {
	// ErrPlatformCAUnavailable and ErrProviderCAUnavailable are the same
	// type (alias). errors.Is must work with either name.
	var platform ErrPlatformCAUnavailable
	var provider ErrProviderCAUnavailable
	if !errors.Is(platform, provider) {
		t.Error("ErrPlatformCAUnavailable must equal ErrProviderCAUnavailable")
	}
}
