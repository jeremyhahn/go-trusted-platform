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

package testutil

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// cov964RecordingTB records Fatalf instead of stopping the test, so the
// failure branches of helpers that take a testing.TB can be asserted.
type cov964RecordingTB struct {
	testing.TB
	fatals []string
}

func (r *cov964RecordingTB) Fatalf(format string, args ...any) {
	r.fatals = append(r.fatals, fmt.Sprintf(format, args...))
}

func TestCov964_ErrNotTLSConnection(t *testing.T) {
	err := fmt.Errorf("accept: %w", ErrNotTLSConnection)

	if got, want := ErrNotTLSConnection.Error(), "testutil: accepted connection is not a TLS connection"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, ErrNotTLSConnection) {
		t.Fatalf("errors.Is(%v, ErrNotTLSConnection) = false, want true", err)
	}
	var typed ErrNotTLSConnectionType
	if !errors.As(err, &typed) {
		t.Fatalf("errors.As(%v, *ErrNotTLSConnectionType) = false, want true", err)
	}
}

func TestCov964_WalkRoutes(t *testing.T) {
	noop := func(http.ResponseWriter, *http.Request) {}
	router := mux.NewRouter()
	router.HandleFunc("/v1/items", noop).Methods(http.MethodGet, http.MethodPost)
	router.HandleFunc("/v1/items/{id}", noop).Methods(http.MethodDelete)
	router.HandleFunc("/v1/any", noop)
	// A route with no path template must be skipped, not listed.
	router.MatcherFunc(func(*http.Request, *mux.RouteMatch) bool { return true }).HandlerFunc(noop)

	got := WalkRoutes(t, router)
	want := []string{
		"DELETE /v1/items/{id}",
		"GET /v1/any",
		"GET /v1/items",
		"POST /v1/items",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WalkRoutes() = %v, want %v", got, want)
	}
}

func TestCov964_RepoFile(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, dir string)
		rel       string
		want      string
		wantFatal string
	}{
		{
			name: "reads a file relative to the go.mod root",
			setup: func(t *testing.T, dir string) {
				cov964WriteFile(t, filepath.Join(dir, "go.mod"), "module example.com/cov964\n")
				cov964WriteFile(t, filepath.Join(dir, "docs", "row.md"), "row content")
			},
			rel:  "docs/row.md",
			want: "row content",
		},
		{
			name:      "no go.mod above the working directory",
			setup:     func(*testing.T, string) {},
			rel:       "docs/row.md",
			wantFatal: "no go.mod found above the working directory",
		},
		{
			name: "missing file under the root",
			setup: func(t *testing.T, dir string) {
				cov964WriteFile(t, filepath.Join(dir, "go.mod"), "module example.com/cov964\n")
			},
			rel:       "docs/missing.md",
			wantFatal: "cannot read docs/missing.md from the repository root",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			t.Chdir(dir)

			rec := &cov964RecordingTB{TB: t}
			got := RepoFile(rec, tc.rel)

			if got != tc.want {
				t.Fatalf("RepoFile() = %q, want %q", got, tc.want)
			}
			if tc.wantFatal == "" {
				if len(rec.fatals) != 0 {
					t.Fatalf("unexpected Fatalf calls: %v", rec.fatals)
				}
				return
			}
			if len(rec.fatals) != 1 || !strings.Contains(rec.fatals[0], tc.wantFatal) {
				t.Fatalf("Fatalf calls = %v, want one containing %q", rec.fatals, tc.wantFatal)
			}
		})
	}
}

func cov964WriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
