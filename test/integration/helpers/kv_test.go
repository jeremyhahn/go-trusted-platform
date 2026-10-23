//go:build integration

package helpers

import (
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
)

func TestKVEntityAbsent(t *testing.T) {
	tests := []struct {
		name string
		resp *quicbaassdk.GetResponse
		err  error
		want bool
	}{
		{"typed not-found error", nil, sdkerrors.NewNotFound("service.Get", "kv/x not found: 7"), true},
		{"database not-found error", nil, quicbaassdk.NewDatabaseError(quicbaassdk.ErrNotFound, "service.Get", "kv/x not found: 7"), true},
		{"database internal error", nil, quicbaassdk.NewDatabaseError(quicbaassdk.ErrInternal, "service.Get", "disk"), false},
		{"response not found", &quicbaassdk.GetResponse{Found: false}, nil, true},
		{"response found", &quicbaassdk.GetResponse{Found: true}, nil, false},
		{"unavailable error", nil, sdkerrors.NewUnavailable("service.Get", "no leader"), false},
		{"nil response and nil error", nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := KVEntityAbsent(tt.resp, tt.err); got != tt.want {
				t.Errorf("KVEntityAbsent() = %v, want %v", got, tt.want)
			}
		})
	}
}
