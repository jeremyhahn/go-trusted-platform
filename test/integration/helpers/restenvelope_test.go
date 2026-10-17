package helpers

import (
	"errors"
	"testing"
)

func TestRESTPayload(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    string
		wantErr bool
	}{
		{"envelope with payload", `{"code":200,"success":true,"payload":{"id":"u1"}}`, `{"id":"u1"}`, false},
		{"envelope without payload", `{"code":200,"success":true}`, ``, false},
		{"empty reply", ``, ``, false},
		{"bare entity is not an envelope", `{"id":"u1"}`, ``, true},
		{"array is not an envelope", `[{"id":"u1"}]`, ``, true},
		{"malformed JSON", `{"success":`, ``, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RESTPayload([]byte(tt.body))
			if tt.wantErr {
				var notEnveloped ErrRESTNotEnveloped
				if !errors.As(err, &notEnveloped) {
					t.Fatalf("RESTPayload(%q) error = %v, want ErrRESTNotEnveloped", tt.body, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("RESTPayload(%q) error = %v", tt.body, err)
			}
			if string(got) != tt.want {
				t.Fatalf("RESTPayload(%q) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}
}
