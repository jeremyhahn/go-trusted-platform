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

package mcpwire

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestClient_RefusesHTTPSToHTTPRedirect checks that a 307 or 308 from an
// https endpoint to a plaintext URL is refused: the client would otherwise
// replay the POST body, secrets included, over plaintext.
func TestClient_RefusesHTTPSToHTTPRedirect(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var plainHits atomic.Int32
			plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				plainHits.Add(1)
				initializeOK(w, r)
			}))
			defer plain.Close()

			secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", plain.URL+"/mcp")
				w.WriteHeader(status)
			}))
			defer secure.Close()

			config := DefaultClientConfig(secure.URL)
			config.TLSConfig = secure.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			config.MaxRetries = 0

			client, err := NewClient(config)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer client.Close()

			_, err = client.CallTool(context.Background(), "platform_tpm_provision",
				map[string]interface{}{"owner_password": "pw"})
			if err == nil {
				t.Error("expected an error for an https to http redirect")
			}
			if got := plainHits.Load(); got != 0 {
				t.Errorf("plaintext server saw %d requests after the redirect, want 0", got)
			}
		})
	}
}
