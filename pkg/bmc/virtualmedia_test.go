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

package bmc

import (
	"errors"
	"testing"
)

func TestMediaSpec_Validate(t *testing.T) {
	cases := []struct {
		name      string
		spec      *MediaSpec
		wantErr   bool
		wantField string
		wantProto MediaProtocol
	}{
		{
			name:      "https url infers protocol",
			spec:      &MediaSpec{URL: "https://example.com/boot.iso"},
			wantProto: MediaProtocolHTTPS,
		},
		{
			name:      "http url infers protocol",
			spec:      &MediaSpec{URL: "http://example.com/boot.iso"},
			wantProto: MediaProtocolHTTP,
		},
		{
			name:      "cifs url infers protocol",
			spec:      &MediaSpec{URL: "cifs://server/share/boot.iso"},
			wantProto: MediaProtocolCIFS,
		},
		{
			name:      "smb scheme normalizes to cifs",
			spec:      &MediaSpec{URL: "smb://server/share/boot.iso"},
			wantProto: MediaProtocolCIFS,
		},
		{
			name:      "explicit protocol matches scheme",
			spec:      &MediaSpec{URL: "https://example.com/boot.iso", Protocol: MediaProtocolHTTPS},
			wantProto: MediaProtocolHTTPS,
		},
		{
			name:      "nil spec",
			spec:      nil,
			wantErr:   true,
			wantField: "spec",
		},
		{
			name:      "empty url",
			spec:      &MediaSpec{},
			wantErr:   true,
			wantField: "URL",
		},
		{
			name:      "blank url",
			spec:      &MediaSpec{URL: "   "},
			wantErr:   true,
			wantField: "URL",
		},
		{
			name:      "missing scheme",
			spec:      &MediaSpec{URL: "example.com/boot.iso"},
			wantErr:   true,
			wantField: "URL",
		},
		{
			name:      "unknown scheme",
			spec:      &MediaSpec{URL: "ftp://example.com/boot.iso"},
			wantErr:   true,
			wantField: "URL",
		},
		{
			name:      "explicit protocol mismatched scheme",
			spec:      &MediaSpec{URL: "https://example.com/boot.iso", Protocol: MediaProtocolCIFS},
			wantErr:   true,
			wantField: "Protocol",
		},
		{
			name:      "unknown explicit protocol",
			spec:      &MediaSpec{URL: "https://example.com/boot.iso", Protocol: MediaProtocol("smb3")},
			wantErr:   true,
			wantField: "Protocol",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.spec.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Validate() = nil, want error")
				}
				var invErr ErrVirtualMediaInvalidSpec
				if !errors.As(err, &invErr) {
					t.Fatalf("Validate() returned %T, want ErrVirtualMediaInvalidSpec", err)
				}
				if tc.wantField != "" && invErr.Field != tc.wantField {
					t.Errorf("Validate() Field = %q, want %q", invErr.Field, tc.wantField)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() error: %v", err)
			}
			if tc.spec.Protocol != tc.wantProto {
				t.Errorf("Protocol = %q, want %q", tc.spec.Protocol, tc.wantProto)
			}
		})
	}
}

func TestMediaProtocol_IsValid(t *testing.T) {
	cases := []struct {
		proto MediaProtocol
		want  bool
	}{
		{MediaProtocolHTTP, true},
		{MediaProtocolHTTPS, true},
		{MediaProtocolCIFS, true},
		{MediaProtocolNFS, true},
		{MediaProtocol(""), false},
		{MediaProtocol("ftp"), false},
	}
	for _, tc := range cases {
		t.Run(string(tc.proto), func(t *testing.T) {
			if got := tc.proto.IsValid(); got != tc.want {
				t.Errorf("IsValid() = %v, want %v", got, tc.want)
			}
		})
	}
}
