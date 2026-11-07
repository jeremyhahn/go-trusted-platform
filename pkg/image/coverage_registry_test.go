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
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloneRequest_WithBody(t *testing.T) {
	body := []byte("hello world")
	req, err := http.NewRequest("POST", "http://example.com", io.NopCloser(bytes.NewReader(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	ctx := context.Background()
	clone, err := cloneRequest(ctx, req)
	require.NoError(t, err)

	cloneBody, err := io.ReadAll(clone.Body)
	require.NoError(t, err)
	assert.Equal(t, body, cloneBody)

	origBody, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, body, origBody)
}

func TestCloneRequest_NilBody(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	require.NoError(t, err)

	ctx := context.Background()
	clone, err := cloneRequest(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, clone)
}

func TestRegistryClient_GetImageDigest_Forbidden(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
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

	_, err = client.GetImageDigest(context.Background(), ref)
	require.Error(t, err)
	var accessDenied ErrRegistryAccessDenied
	assert.ErrorAs(t, err, &accessDenied)
}

func TestRegistryClient_GetImageDigest_ServerError(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	client, err := NewRegistryClient(&RegistryOptions{
		MaxRetries: 1,
		RetryDelay: time.Millisecond,
		CACertPool: caPool,
	})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	_, err = client.GetImageDigest(context.Background(), ref)
	require.Error(t, err)
}

func TestRegistryClient_GetImageDigest_NoDigest(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	_, err = client.GetImageDigest(context.Background(), ref)
	require.Error(t, err)
	var invalidManifest ErrInvalidManifest
	assert.ErrorAs(t, err, &invalidManifest)
}

func TestRegistryClient_GetImageDigest_OCIDigest(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("OCI-Content-Digest", "sha256:oci123")
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
	assert.Equal(t, "sha256:oci123", digest)
}

func TestRegistryClient_GetImageDigest_BadRequest(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
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

	_, err = client.GetImageDigest(context.Background(), ref)
	require.Error(t, err)
	var unavailable ErrRegistryUnavailable
	assert.ErrorAs(t, err, &unavailable)
}

func TestRegistryClient_GetImageDigest_NoTag(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Content-Digest", "sha256:defaulttag")
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
	}

	digest, err := client.GetImageDigest(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "sha256:defaulttag", digest)
}

func TestRegistryClient_GetImageDigest_ContextCanceled(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	_, err = client.GetImageDigest(ctx, ref)
	require.Error(t, err)
}

func TestRegistryClient_PullSignature_Forbidden(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
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
		Digest:     "sha256:abc123",
	}

	_, err = client.PullSignature(context.Background(), ref)
	require.Error(t, err)
}

func TestRegistryClient_PushSignature_Forbidden(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
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
		Digest:     "sha256:abc123",
	}

	sig := &ImageSignature{
		SignatureAlgorithm: AlgorithmRSA256,
		Signature:          []byte("sig"),
		Payload:            []byte("payload"),
	}

	err = client.PushSignature(context.Background(), ref, sig)
	require.Error(t, err)
}
