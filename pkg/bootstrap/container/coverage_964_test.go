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

package container

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
)

// cov964Cause is the underlying error every wrapping error in the table
// carries, so errors.Is can find it through Unwrap.
type cov964Cause struct{}

func (cov964Cause) Error() string { return "disk on fire" }

var errCov964Cause = cov964Cause{}

// TestErrors_MessageAndUnwrap pins the message of each typed error and, for
// the wrapping ones, that errors.Is and errors.As reach the cause.
func TestErrors_MessageAndUnwrap(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		want    string
		wrapped bool
	}{
		{
			name: "manifest not found",
			err:  ErrManifestNotFound{Path: "/m.yaml"},
			want: "container: manifest not found: /m.yaml",
		},
		{
			name: "MAC not in manifest",
			err:  ErrMACNotInManifest{MAC: "aa:bb"},
			want: "container: MAC aa:bb not in manifest",
		},
		{
			name: "invalid server config",
			err:  ErrInvalidServerConfig{Field: "listen_addr", Reason: "empty"},
			want: "container: invalid config: field listen_addr: empty",
		},
		{
			name:    "manifest write",
			err:     ErrManifestWrite{Path: "/m.yaml", Cause: errCov964Cause},
			want:    "container: failed to write manifest to /m.yaml: disk on fire",
			wrapped: true,
		},
		{
			name:    "manifest read",
			err:     ErrManifestRead{Path: "/m.yaml", Cause: errCov964Cause},
			want:    "container: failed to read manifest from /m.yaml: disk on fire",
			wrapped: true,
		},
		{
			name:    "manifest parse",
			err:     ErrManifestParse{Path: "/m.yaml", Cause: errCov964Cause},
			want:    "container: failed to parse manifest from /m.yaml: disk on fire",
			wrapped: true,
		},
		{
			name: "message error",
			err:  &MessageError{Msg: "plain message"},
			want: "plain message",
		},
		{
			name:    "media set",
			err:     ErrMediaSet{Path: "/sets/a", Reason: "unreadable", Err: errCov964Cause},
			want:    "bootstrap container: media set /sets/a: unreadable: disk on fire",
			wrapped: true,
		},
		{
			name: "unknown media set by name",
			err:  ErrUnknownMediaSet{MAC: "aa:bb", MediaSet: "edge"},
			want: "bootstrap container: aa:bb boots media set edge, which is not staged",
		},
		{
			name: "unknown media set by architecture",
			err:  ErrUnknownMediaSet{MAC: "aa:bb", Architecture: "arm64"},
			want: "bootstrap container: aa:bb is arm64 and no media set is that architecture's default",
		},
		{
			name:    "nbd server address",
			err:     ErrNBDServerAddress{ListenAddr: ":10809", Err: errCov964Cause},
			want:    `bootstrap container: nbd.listen_addr ":10809" names no address a diskless-nbd node can dial: disk on fire`,
			wrapped: true,
		},
		{
			name:    "netboot media",
			err:     ErrNetbootMedia{Path: "/nb", Reason: "no index", Err: errCov964Cause},
			want:    "bootstrap container: netboot media /nb: no index: disk on fire",
			wrapped: true,
		},
		{
			name:    "payload list",
			err:     ErrPayloadList{Line: 3, Reason: "bad digest", Err: errCov964Cause},
			want:    "bootstrap container: payload list line 3: bad digest: disk on fire",
			wrapped: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Fatalf("Error() = %q, want %q", got, tt.want)
			}
			if got := errors.Is(tt.err, errCov964Cause); got != tt.wrapped {
				t.Fatalf("errors.Is(cause) = %v, want %v", got, tt.wrapped)
			}
			var cause cov964Cause
			if got := errors.As(tt.err, &cause); got != tt.wrapped {
				t.Fatalf("errors.As(cause) = %v, want %v", got, tt.wrapped)
			}
		})
	}
}

// TestErrors_UnwrapNilCause checks that a wrapping error built without a
// cause unwraps to nil rather than to a stale or synthetic error.
func TestErrors_UnwrapNilCause(t *testing.T) {
	tests := []struct {
		name string
		err  interface{ Unwrap() error }
	}{
		{"media set", ErrMediaSet{Path: "/sets/a", Reason: "missing"}},
		{"nbd server address", ErrNBDServerAddress{ListenAddr: ":1"}},
		{"netboot media", ErrNetbootMedia{Path: "/nb", Reason: "missing"}},
		{"payload list", ErrPayloadList{Reason: "empty"}},
		{"manifest parse", ErrManifestParse{Path: "/m.yaml"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Unwrap(); got != nil {
				t.Fatalf("Unwrap() = %v, want nil", got)
			}
		})
	}
}

// TestErrMACNotInManifest_IsDeviceNotFound checks that a MAC the manifest
// lacks reads as the device lookup's not-found, and only as that.
func TestErrMACNotInManifest_IsDeviceNotFound(t *testing.T) {
	err := error(ErrMACNotInManifest{MAC: "aa:bb"})
	if !errors.Is(err, ipxe.ErrDeviceNotFound) {
		t.Fatal("errors.Is(ErrMACNotInManifest, ipxe.ErrDeviceNotFound) = false, want true")
	}
	if errors.Is(err, errCov964Cause) {
		t.Fatal("errors.Is(ErrMACNotInManifest, unrelated) = true, want false")
	}
}
