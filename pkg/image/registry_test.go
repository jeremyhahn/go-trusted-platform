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

package image

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRegistryClient(t *testing.T) {
	tests := []struct {
		name      string
		opts      *RegistryOptions
		expectErr bool
	}{
		{
			name:      "nil options",
			opts:      nil,
			expectErr: false,
		},
		{
			name:      "empty options",
			opts:      &RegistryOptions{},
			expectErr: false,
		},
		{
			name: "with auth",
			opts: &RegistryOptions{
				Auth: &RegistryAuth{
					Username: "user",
					Password: "pass",
				},
			},
			expectErr: false,
		},
		{
			name: "with custom timeout",
			opts: &RegistryOptions{
				Timeout:    60 * time.Second,
				MaxRetries: 5,
				RetryDelay: 2 * time.Second,
			},
			expectErr: false,
		},
		{
			name:      "insecure mode",
			opts:      &RegistryOptions{},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewRegistryClient(tt.opts)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestRegistryClient_BuildURL(t *testing.T) {
	client, err := NewRegistryClient(&RegistryOptions{})
	require.NoError(t, err)

	tests := []struct {
		name     string
		ref      *ImageReference
		path     string
		expected string
	}{
		{
			name: "custom registry",
			ref: &ImageReference{
				Registry:   "gcr.io",
				Repository: "project/image",
			},
			path:     "/v2/project/image/manifests/latest",
			expected: "https://gcr.io/v2/project/image/manifests/latest",
		},
		{
			name: "docker hub",
			ref: &ImageReference{
				Registry:   "docker.io",
				Repository: "library/nginx",
			},
			path:     "/v2/library/nginx/manifests/latest",
			expected: "https://registry-1.docker.io/v2/library/nginx/manifests/latest",
		},
		{
			name: "empty registry defaults to docker.io",
			ref: &ImageReference{
				Repository: "library/nginx",
			},
			path:     "/v2/library/nginx/manifests/latest",
			expected: "https://registry-1.docker.io/v2/library/nginx/manifests/latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := client.buildURL(tt.ref, tt.path)
			assert.Equal(t, tt.expected, url)
		})
	}
}

func TestRegistryClient_BuildURL_AlwaysHTTPS(t *testing.T) {
	client, err := NewRegistryClient(&RegistryOptions{})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   "localhost:5000",
		Repository: "myimage",
	}

	url := client.buildURL(ref, "/v2/myimage/manifests/latest")
	assert.Contains(t, url, "https://")
}

func TestRegistryClient_SetAuthHeader(t *testing.T) {
	tests := []struct {
		name     string
		auth     *RegistryAuth
		expected string
	}{
		{
			name:     "no auth",
			auth:     nil,
			expected: "",
		},
		{
			name: "bearer token",
			auth: &RegistryAuth{
				Token: "mytoken123",
			},
			expected: "Bearer mytoken123",
		},
		{
			name: "basic auth",
			auth: &RegistryAuth{
				Username: "user",
				Password: "pass",
			},
			expected: "Basic dXNlcjpwYXNz", // base64 of user:pass
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewRegistryClient(&RegistryOptions{
				Auth: tt.auth,
			})
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
			client.setAuthHeader(req, "example.com")

			assert.Equal(t, tt.expected, req.Header.Get("Authorization"))
		})
	}
}

func TestRegistryClient_SetUserAgent(t *testing.T) {
	client, err := NewRegistryClient(&RegistryOptions{
		UserAgent: "custom-agent/1.0",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	client.setUserAgent(req)

	assert.Equal(t, "custom-agent/1.0", req.Header.Get("User-Agent"))
}

func TestRegistryClient_Close(t *testing.T) {
	client, err := NewRegistryClient(&RegistryOptions{})
	require.NoError(t, err)

	err = client.Close()
	assert.NoError(t, err)
	assert.True(t, client.closed.Load())
}

func TestRegistryClient_ClosedClient(t *testing.T) {
	client, err := NewRegistryClient(&RegistryOptions{})
	require.NoError(t, err)

	err = client.Close()
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Tag:        "latest",
	}

	// All operations should fail on closed client
	_, err = client.GetImageManifest(context.Background(), ref)
	assert.Error(t, err)

	_, err = client.GetImageDigest(context.Background(), ref)
	assert.Error(t, err)

	_, err = client.PullSignature(context.Background(), ref)
	assert.Error(t, err)

	err = client.PushSignature(context.Background(), ref, &ImageSignature{})
	assert.Error(t, err)
}

func TestRegistryClient_NilRef(t *testing.T) {
	client, err := NewRegistryClient(&RegistryOptions{})
	require.NoError(t, err)

	_, err = client.GetImageManifest(context.Background(), nil)
	assert.Error(t, err)

	_, err = client.GetImageDigest(context.Background(), nil)
	assert.Error(t, err)

	_, err = client.PullSignature(context.Background(), nil)
	assert.Error(t, err)

	err = client.PushSignature(context.Background(), nil, &ImageSignature{})
	assert.Error(t, err)
}

func TestRegistryClient_PushSignature_NilSig(t *testing.T) {
	client, err := NewRegistryClient(&RegistryOptions{})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Tag:        "latest",
	}

	err = client.PushSignature(context.Background(), ref, nil)
	assert.Error(t, err)
}

func TestRegistryClient_GetImageManifest_MockServer(t *testing.T) {
	manifest := `{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json"}`

	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/myimage/manifests/latest", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Docker-Content-Digest", "sha256:abc123")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(manifest)); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}))
	defer server.Close()

	client, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	// Extract host from server URL
	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	result, err := client.GetImageManifest(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, []byte(manifest), result)
}

func TestRegistryClient_GetImageManifest_NotFound(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	_, err = client.GetImageManifest(context.Background(), ref)
	assert.Error(t, err)
	assert.IsType(t, ErrImageNotFound{}, err)
}

func TestRegistryClient_GetImageManifest_Unauthorized(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	_, err = client.GetImageManifest(context.Background(), ref)
	assert.Error(t, err)
	assert.IsType(t, ErrRegistryAccessDenied{}, err)
}

func TestRegistryClient_GetImageDigest_MockServer(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodHead, r.Method)
		w.Header().Set("Docker-Content-Digest", "sha256:abc123def456")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	digest, err := client.GetImageDigest(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "sha256:abc123def456", digest)
}

func TestRegistryClient_GetImageDigest_ExistingDigest(t *testing.T) {
	client, err := NewRegistryClient(&RegistryOptions{})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Digest:     "sha256:existingdigest123",
	}

	digest, err := client.GetImageDigest(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "sha256:existingdigest123", digest)
}

func TestRegistryClient_PullSignature_MockServer(t *testing.T) {
	sig := &ImageSignature{
		ImageDigest: "sha256:abc123",
		Signature:   []byte("signature"),
		Timestamp:   time.Now(),
	}

	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/vnd.dev.cosign.simplesigning.v1+json")
		if err := json.NewEncoder(w).Encode(sig); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}))
	defer server.Close()

	client, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	result, err := client.PullSignature(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, sig.ImageDigest, result.ImageDigest)
}

func TestRegistryClient_PullSignature_NotFound(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	_, err = client.PullSignature(context.Background(), ref)
	assert.Error(t, err)
	assert.IsType(t, ErrSignatureNotFound{}, err)
}

func TestRegistryClient_PushSignature_MockServer(t *testing.T) {
	var receivedSig ImageSignature

	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "application/vnd.dev.cosign.simplesigning.v1+json", r.Header.Get("Content-Type"))

		if err := json.NewDecoder(r.Body).Decode(&receivedSig); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	sig := &ImageSignature{
		ImageDigest: "sha256:abc123",
		Signature:   []byte("signature"),
		Timestamp:   time.Now(),
	}

	err = client.PushSignature(context.Background(), ref, sig)
	require.NoError(t, err)
	assert.Equal(t, sig.ImageDigest, receivedSig.ImageDigest)
}

func TestRegistryClient_Retry_ServerError(t *testing.T) {
	attempts := 0
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Docker-Content-Digest", "sha256:abc123")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"schemaVersion": 2}`)); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}))
	defer server.Close()

	client, err := NewRegistryClient(&RegistryOptions{
		MaxRetries: 3,
		RetryDelay: 10 * time.Millisecond,
		CACertPool: caPool,
	})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	_, err = client.GetImageManifest(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, 3, attempts)
}

func TestSignatureCache(t *testing.T) {
	cache := NewSignatureCache(time.Hour)

	sig := &ImageSignature{
		ImageDigest: "sha256:abc123",
		Signature:   []byte("signature"),
	}

	// Test Set and Get
	cache.Set("key1", sig)
	result, ok := cache.Get("key1")
	assert.True(t, ok)
	assert.Equal(t, sig.ImageDigest, result.ImageDigest)

	// Test Get non-existent key
	_, ok = cache.Get("nonexistent")
	assert.False(t, ok)

	// Test Delete
	cache.Delete("key1")
	_, ok = cache.Get("key1")
	assert.False(t, ok)

	// Test Clear
	cache.Set("key2", sig)
	cache.Set("key3", sig)
	cache.Clear()
	_, ok = cache.Get("key2")
	assert.False(t, ok)
	_, ok = cache.Get("key3")
	assert.False(t, ok)
}

func TestSignatureCache_Expiry(t *testing.T) {
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cache := NewSignatureCache(time.Minute)
	cache.now = func() time.Time { return current }

	sig := &ImageSignature{
		ImageDigest: "sha256:abc123",
	}

	cache.Set("key1", sig)

	// Set stamps the entry from the cache's clock.
	stored, ok := cache.cache.Load("key1")
	require.True(t, ok)
	entry := stored.(*CacheEntry)
	assert.Equal(t, current, entry.CreatedAt)
	assert.Equal(t, current.Add(time.Minute), entry.ExpiresAt)

	// Still valid at exactly the TTL: expiry is strictly after ExpiresAt.
	current = current.Add(time.Minute)
	_, ok = cache.Get("key1")
	assert.True(t, ok)

	// Expired one tick past the TTL, and evicted on that read.
	current = current.Add(time.Nanosecond)
	_, ok = cache.Get("key1")
	assert.False(t, ok)
	_, ok = cache.cache.Load("key1")
	assert.False(t, ok, "expired entry should be evicted")
}

func TestCachingRegistryClient(t *testing.T) {
	callCount := 0
	sig := &ImageSignature{
		ImageDigest: "sha256:abc123",
		Signature:   []byte("signature"),
		Timestamp:   time.Now(),
	}

	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/vnd.dev.cosign.simplesigning.v1+json")
		if err := json.NewEncoder(w).Encode(sig); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}))
	defer server.Close()

	innerClient, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	client := NewCachingRegistryClient(innerClient, time.Hour)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	// First call should hit the server
	result1, err := client.PullSignature(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Second call should use cache
	result2, err := client.PullSignature(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount) // No additional calls

	assert.Equal(t, result1.ImageDigest, result2.ImageDigest)
}

func TestCachingRegistryClient_InvalidateCache(t *testing.T) {
	callCount := 0
	sig := &ImageSignature{
		ImageDigest: "sha256:abc123",
		Signature:   []byte("signature"),
		Timestamp:   time.Now(),
	}

	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/vnd.dev.cosign.simplesigning.v1+json")
		if err := json.NewEncoder(w).Encode(sig); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}))
	defer server.Close()

	innerClient, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	client := NewCachingRegistryClient(innerClient, time.Hour)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	// First call
	_, err = client.PullSignature(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Invalidate cache
	client.InvalidateCache(ref)

	// Should hit server again
	_, err = client.PullSignature(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
}

func TestCachingRegistryClient_PushSignature(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	innerClient, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	client := NewCachingRegistryClient(innerClient, time.Hour)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	sig := &ImageSignature{
		ImageDigest: "sha256:abc123",
		Signature:   []byte("signature"),
	}

	// Push should cache the signature
	err = client.PushSignature(context.Background(), ref, sig)
	require.NoError(t, err)

	// Subsequent pull should use cache (no server call)
	result, err := client.PullSignature(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, sig.ImageDigest, result.ImageDigest)
}

func TestCachingRegistryClient_Close(t *testing.T) {
	innerClient, err := NewRegistryClient(&RegistryOptions{})
	require.NoError(t, err)

	client := NewCachingRegistryClient(innerClient, time.Hour)

	// Add something to cache
	client.cache.Set("key", &ImageSignature{})

	err = client.Close()
	assert.NoError(t, err)

	// Cache should be cleared
	_, ok := client.cache.Get("key")
	assert.False(t, ok)
}

func TestCachingRegistryClient_GetImageManifest(t *testing.T) {
	manifest := `{"schemaVersion": 2}`

	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(manifest)); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}))
	defer server.Close()

	innerClient, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	client := NewCachingRegistryClient(innerClient, time.Hour)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	result, err := client.GetImageManifest(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, []byte(manifest), result)
}

func TestCachingRegistryClient_GetImageDigest(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Content-Digest", "sha256:abc123")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	innerClient, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	client := NewCachingRegistryClient(innerClient, time.Hour)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	digest, err := client.GetImageDigest(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "sha256:abc123", digest)
}
