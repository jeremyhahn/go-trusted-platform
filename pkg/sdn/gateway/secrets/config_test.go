// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package secrets

import (
	"errors"
	"testing"
	"time"
)

func TestConfigValidate_Accepts(t *testing.T) {
	cases := []Config{
		{QuicBaaSAddr: "10.4.2.140:9443"},
		{QuicBaaSAddr: "/run/quicbaasd.sock", QuicBaaSTransport: "unix"},
		{QuicBaaSAddr: "h:1", QuicBaaSTransport: "grpc", Timeout: 5 * time.Second},
		{QuicBaaSAddr: "h:1", QuicBaaSTransport: "rest"},
		{QuicBaaSAddr: "h:1", QuicBaaSTransport: "quic"},
		{QuicBaaSAddr: "h:1", QuicBaaSTransport: "mcp"},
	}
	for _, c := range cases {
		if err := c.Validate(); err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
	}
}

func TestConfigValidate_Refuses(t *testing.T) {
	cases := []struct {
		name  string
		cfg   Config
		field string
	}{
		{"missing addr", Config{}, "quicbaas-addr"},
		{"unknown transport", Config{QuicBaaSAddr: "h:1", QuicBaaSTransport: "smoke-signal"}, "quicbaas-transport"},
		{"negative timeout", Config{QuicBaaSAddr: "h:1", Timeout: -time.Second}, "timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			var want *ErrConfigInvalid
			if !errors.As(err, &want) {
				t.Fatalf("got %v, want ErrConfigInvalid", err)
			}
			if want.Field != tc.field {
				t.Fatalf("field %q, want %q", want.Field, tc.field)
			}
		})
	}
}

func TestEffectiveTimeout(t *testing.T) {
	if got := (&Config{}).EffectiveTimeout(); got != DefaultTimeout {
		t.Fatalf("zero timeout resolved to %v", got)
	}
	if got := (&Config{Timeout: time.Second}).EffectiveTimeout(); got != time.Second {
		t.Fatalf("explicit timeout resolved to %v", got)
	}
}
