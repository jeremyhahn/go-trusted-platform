package proxy

import (
	"net/http"
	"testing"
)

func fullIdentity() *ClientIdentity {
	return &ClientIdentity{
		ID:              "client-1",
		DeviceID:        "ab12",
		Zone:            "trusted",
		AuthMethod:      "mtls",
		CertFingerprint: "deadbeef",
		Attested:        false,
		subjectDN:       "CN=device-1,O=Test Org",
		uriSAN:          "spiffe://platform/device-1",
	}
}

func TestInjectIdentityFull(t *testing.T) {
	h := http.Header{}
	injectIdentity(h, fullIdentity())
	want := map[string]string{
		headerForwardedClientCert: `Hash=deadbeef;Subject="CN=device-1,O=Test Org";URI=spiffe://platform/device-1`,
		headerTPClientID:          "client-1",
		headerTPDeviceID:          "ab12",
		headerTPClientZone:        "trusted",
		headerTPAuthMethod:        "mtls",
		headerTPAttested:          "false",
		headerTPCertFingerprint:   "deadbeef",
	}
	for k, v := range want {
		if got := h.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

func TestInjectIdentityNil(t *testing.T) {
	h := http.Header{}
	injectIdentity(h, nil)
	if len(h) != 0 {
		t.Errorf("nil identity must inject nothing, got %v", h)
	}
}

func TestInjectIdentityOmitsEmptyFields(t *testing.T) {
	h := http.Header{}
	injectIdentity(h, &ClientIdentity{Attested: true})
	for _, k := range []string{
		headerForwardedClientCert, headerTPClientID, headerTPDeviceID,
		headerTPClientZone, headerTPAuthMethod, headerTPCertFingerprint,
		headerAuthorization,
	} {
		if got := h.Get(k); got != "" {
			t.Errorf("%s = %q, want unset", k, got)
		}
	}
	if got := h.Get(headerTPAttested); got != "true" {
		t.Errorf("%s = %q, want true (always set)", headerTPAttested, got)
	}
}

func TestInjectIdentityNeverSetsAuthorization(t *testing.T) {
	h := http.Header{}
	injectIdentity(h, fullIdentity())
	if got := h.Get(headerAuthorization); got != "" {
		t.Errorf("Authorization = %q, want unset — the proxy never injects backend credentials", got)
	}
}

func TestBuildXFCC(t *testing.T) {
	tests := []struct {
		name string
		id   *ClientIdentity
		want string
	}{
		{"all elements", fullIdentity(),
			`Hash=deadbeef;Subject="CN=device-1,O=Test Org";URI=spiffe://platform/device-1`},
		{"hash only", &ClientIdentity{CertFingerprint: "aa"}, "Hash=aa"},
		{"subject only", &ClientIdentity{subjectDN: "CN=x"}, `Subject="CN=x"`},
		{"uri only", &ClientIdentity{uriSAN: "spiffe://x"}, "URI=spiffe://x"},
		{"no cert detail", &ClientIdentity{ID: "c"}, ""},
		{"subject with quotes and backslash",
			&ClientIdentity{subjectDN: `CN=a"b\c`}, `Subject="CN=a\"b\\c"`},
		{"uri with semicolon quoted",
			&ClientIdentity{uriSAN: "urn:x;y"}, `URI="urn:x;y"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildXFCC(tt.id); got != tt.want {
				t.Errorf("buildXFCC = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestXFCCValue(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"plain", "plain"},
		{"has,comma", `"has,comma"`},
		{"has;semi", `"has;semi"`},
		{"has=eq", `"has=eq"`},
		{`has"quote`, `"has\"quote"`},
	}
	for _, tt := range tests {
		if got := xfccValue(tt.in); got != tt.want {
			t.Errorf("xfccValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestXFCCEscape(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"plain", "plain"},
		{`a"b`, `a\"b`},
		{`a\b`, `a\\b`},
		{`a\"b`, `a\\\"b`},
	}
	for _, tt := range tests {
		if got := xfccEscape(tt.in); got != tt.want {
			t.Errorf("xfccEscape(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
