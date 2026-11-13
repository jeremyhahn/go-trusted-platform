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

package v1

import (
	"testing"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigStruct(t *testing.T) {
	t.Run("creates config with all fields", func(t *testing.T) {
		config := Config{
			Name:    "test-service",
			Home:    "/var/www",
			Index:   "index.html",
			Port:    8080,
			TLSPort: 8443,
		}

		assert.Equal(t, "test-service", config.Name)
		assert.Equal(t, "/var/www", config.Home)
		assert.Equal(t, "index.html", config.Index)
		assert.Equal(t, 8080, config.Port)
		assert.Equal(t, 8443, config.TLSPort)
	})

	t.Run("supports zero values", func(t *testing.T) {
		config := Config{}

		assert.Empty(t, config.Name)
		assert.Empty(t, config.Home)
		assert.Empty(t, config.Index)
		assert.Zero(t, config.Port)
		assert.Zero(t, config.TLSPort)
		assert.Nil(t, config.ACME)
		assert.Nil(t, config.Key)
		assert.Nil(t, config.RateLimit)
		assert.Empty(t, config.Surface)
		assert.Nil(t, config.VirtualHosts)
		assert.Nil(t, config.WebAuthn)
		assert.Nil(t, config.CORS)
	})

	t.Run("nested ACME config", func(t *testing.T) {
		config := Config{
			ACME: &ACMEConfig{
				Enabled:                 true,
				DirectoryURL:            "https://acme.example.com/directory",
				TermsOfService:          "https://example.com/tos",
				Challenges:              []string{"http-01", "dns-01"},
				ExternalAccountRequired: true,
			},
		}

		require.NotNil(t, config.ACME)
		assert.True(t, config.ACME.Enabled)
		assert.Equal(t, "https://acme.example.com/directory", config.ACME.DirectoryURL)
		assert.Equal(t, "https://example.com/tos", config.ACME.TermsOfService)
		assert.Len(t, config.ACME.Challenges, 2)
		assert.True(t, config.ACME.ExternalAccountRequired)
	})

	t.Run("nested CORS config", func(t *testing.T) {
		config := Config{
			CORS: &CORSConfig{
				AllowedOrigins:   []string{"https://example.com", "https://api.example.com"},
				AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
				AllowedHeaders:   []string{"Content-Type", "Authorization"},
				AllowCredentials: true,
			},
		}

		require.NotNil(t, config.CORS)
		assert.Len(t, config.CORS.AllowedOrigins, 2)
		assert.Contains(t, config.CORS.AllowedOrigins, "https://example.com")
		assert.Len(t, config.CORS.AllowedMethods, 4)
		assert.Len(t, config.CORS.AllowedHeaders, 2)
		assert.True(t, config.CORS.AllowCredentials)
	})

	t.Run("nested JWT config", func(t *testing.T) {
		config := Config{
			JWT: JWT{
				Expiration: 3600,
				Issuer:     "test-issuer",
			},
		}

		assert.Equal(t, int64(3600), config.JWT.Expiration)
		assert.Equal(t, "test-issuer", config.JWT.Issuer)
	})

	t.Run("virtual host proxy config", func(t *testing.T) {
		// The proxy block lives on a virtual host; the top-level Config.Proxy
		// that used to sit beside it was parsed and never read (#571).
		vhosts := []VirtualHost{{
			Hosts: []string{"app.example.com"},
			Proxy: &ProxyConfig{Backends: []string{"http://backend1:8080", "http://backend2:8080"}},
		}}
		config := Config{VirtualHosts: &vhosts}

		require.NotNil(t, (*config.VirtualHosts)[0].Proxy)
		assert.Len(t, (*config.VirtualHosts)[0].Proxy.Backends, 2)
		assert.Contains(t, (*config.VirtualHosts)[0].Proxy.Backends, "http://backend1:8080")
	})

	t.Run("surface and limits", func(t *testing.T) {
		config := Config{Surface: SurfaceEdge, MaxHeaderBytes: 4096, MaxConnections: 10,
			RateLimit: &RateLimitConfig{RequestsPerSecond: 5, Burst: 10}}
		assert.Equal(t, "edge", config.Surface)
		assert.Equal(t, 4096, config.MaxHeaderBytes)
		assert.Equal(t, float64(5), config.RateLimit.RequestsPerSecond)
	})

	t.Run("rewrite rules", func(t *testing.T) {
		config := Config{
			RewriteRules: []*RewriteRule{
				{Pattern: "^/old-path$", Target: "/new-path"},
				{Pattern: "^/legacy/(.*)", Target: "/v2/$1"},
			},
		}

		require.Len(t, config.RewriteRules, 2)
		assert.Equal(t, "^/old-path$", config.RewriteRules[0].Pattern)
		assert.Equal(t, "/new-path", config.RewriteRules[0].Target)
	})

	t.Run("virtual hosts", func(t *testing.T) {
		hosts := []VirtualHost{
			{
				Hosts: []string{"api.example.com"},
				Home:  "/var/www/api",
				Index: "index.html",
			},
			{
				Hosts: []string{"www.example.com", "example.com"},
				Home:  "/var/www/main",
				Index: "index.html",
			},
		}
		config := Config{
			VirtualHosts: &hosts,
		}

		require.NotNil(t, config.VirtualHosts)
		assert.Len(t, *config.VirtualHosts, 2)
	})

	t.Run("webauthn config", func(t *testing.T) {
		config := Config{
			WebAuthn: &WebAuthn{
				RPDisplayName: "Test Application",
				RPID:          "example.com",
				RPOrigins:     []string{"https://example.com", "https://api.example.com"},
			},
		}

		require.NotNil(t, config.WebAuthn)
		assert.Equal(t, "Test Application", config.WebAuthn.RPDisplayName)
		assert.Equal(t, "example.com", config.WebAuthn.RPID)
		assert.Len(t, config.WebAuthn.RPOrigins, 2)
	})

	t.Run("key config", func(t *testing.T) {
		config := Config{
			Key: &common.KeyConfig{
				Hash:               "SHA256",
				KeyAlgorithm:       "ECDSA",
				SignatureAlgorithm: "ECDSAWithSHA256",
			},
		}

		require.NotNil(t, config.Key)
		assert.Equal(t, "SHA256", config.Key.Hash)
		assert.Equal(t, "ECDSA", config.Key.KeyAlgorithm)
		assert.Equal(t, "ECDSAWithSHA256", config.Key.SignatureAlgorithm)
	})
}

func TestACMEConfigStruct(t *testing.T) {
	t.Run("zero values", func(t *testing.T) {
		config := ACMEConfig{}

		assert.False(t, config.Enabled)
		assert.Empty(t, config.DirectoryURL)
		assert.Empty(t, config.TermsOfService)
		assert.Nil(t, config.Challenges)
		assert.False(t, config.ExternalAccountRequired)
	})

	t.Run("all fields set", func(t *testing.T) {
		config := ACMEConfig{
			Enabled:                 true,
			DirectoryURL:            "https://acme.example.com/directory",
			TermsOfService:          "https://example.com/tos",
			Challenges:              []string{"http-01", "dns-01", "tls-alpn-01"},
			ExternalAccountRequired: true,
		}

		assert.True(t, config.Enabled)
		assert.Equal(t, "https://acme.example.com/directory", config.DirectoryURL)
		assert.Len(t, config.Challenges, 3)
	})
}

func TestIdentityStruct(t *testing.T) {
	t.Run("zero values", func(t *testing.T) {
		identity := Identity{}

		assert.Nil(t, identity.ACME)
		assert.Nil(t, identity.SANS)
		assert.Zero(t, identity.Valid)
	})

	t.Run("with subject", func(t *testing.T) {
		identity := Identity{
			Subject: trustedca.CASubject{
				CommonName:   "example.com",
				Organization: "Test Org",
				Country:      "US",
			},
			Valid: 365,
		}

		assert.Equal(t, "example.com", identity.Subject.CommonName)
		assert.Equal(t, "Test Org", identity.Subject.Organization)
		assert.Equal(t, "US", identity.Subject.Country)
		assert.Equal(t, 365, identity.Valid)
	})

	t.Run("with SANS", func(t *testing.T) {
		identity := Identity{
			SANS: &trustedca.CASubjectAlternativeNames{
				DNS:   []string{"www.example.com", "api.example.com"},
				IPs:   []string{"192.168.1.1"},
				Email: []string{"admin@example.com"},
			},
		}

		require.NotNil(t, identity.SANS)
		assert.Len(t, identity.SANS.DNS, 2)
		assert.Len(t, identity.SANS.IPs, 1)
		assert.Len(t, identity.SANS.Email, 1)
	})
}

func TestProxyConfigStruct(t *testing.T) {
	t.Run("zero values", func(t *testing.T) {
		proxy := ProxyConfig{}

		assert.Nil(t, proxy.Backends)
	})

	t.Run("with backends", func(t *testing.T) {
		proxy := ProxyConfig{
			Backends: []string{
				"http://localhost:3001",
				"http://localhost:3002",
				"http://localhost:3003",
			},
		}

		assert.Len(t, proxy.Backends, 3)
	})
}

func TestRewriteRuleStruct(t *testing.T) {
	t.Run("zero values", func(t *testing.T) {
		rule := RewriteRule{}

		assert.Empty(t, rule.Pattern)
		assert.Empty(t, rule.Target)
	})

	t.Run("with pattern and target", func(t *testing.T) {
		rule := RewriteRule{
			Pattern: "^/api/v1/(.*)",
			Target:  "/api/v2/$1",
		}

		assert.Equal(t, "^/api/v1/(.*)", rule.Pattern)
		assert.Equal(t, "/api/v2/$1", rule.Target)
	})
}

func TestVirtualHostStruct(t *testing.T) {
	t.Run("zero values", func(t *testing.T) {
		vhost := VirtualHost{}

		assert.Nil(t, vhost.Certificate)
		assert.Nil(t, vhost.CORS)
		assert.Empty(t, vhost.Home)
		assert.Nil(t, vhost.Hosts)
		assert.Empty(t, vhost.Index)
		assert.Nil(t, vhost.Key)
		assert.Nil(t, vhost.Proxy)
		assert.Nil(t, vhost.RewriteRules)
	})

	t.Run("complete virtual host", func(t *testing.T) {
		vhost := VirtualHost{
			Hosts: []string{"www.example.com", "example.com"},
			Home:  "/var/www/example",
			Index: "index.html",
			CORS: &CORSConfig{
				AllowedOrigins: []string{"*"},
			},
			Certificate: &Identity{
				Subject: trustedca.CASubject{
					CommonName: "www.example.com",
				},
				Valid: 365,
			},
			RewriteRules: []*RewriteRule{
				{Pattern: "^/old$", Target: "/new"},
			},
		}

		assert.Len(t, vhost.Hosts, 2)
		assert.Equal(t, "/var/www/example", vhost.Home)
		assert.Equal(t, "index.html", vhost.Index)
		require.NotNil(t, vhost.CORS)
		require.NotNil(t, vhost.Certificate)
		require.Len(t, vhost.RewriteRules, 1)
	})
}

func TestWebAuthnStruct(t *testing.T) {
	t.Run("zero values", func(t *testing.T) {
		webauthn := WebAuthn{}

		assert.Empty(t, webauthn.RPDisplayName)
		assert.Empty(t, webauthn.RPID)
		assert.Nil(t, webauthn.RPOrigins)
	})

	t.Run("complete config", func(t *testing.T) {
		webauthn := WebAuthn{
			RPDisplayName: "My Application",
			RPID:          "app.example.com",
			RPOrigins:     []string{"https://app.example.com"},
		}

		assert.Equal(t, "My Application", webauthn.RPDisplayName)
		assert.Equal(t, "app.example.com", webauthn.RPID)
		assert.Len(t, webauthn.RPOrigins, 1)
	})
}

func TestCORSConfigStruct(t *testing.T) {
	t.Run("zero values", func(t *testing.T) {
		cors := CORSConfig{}

		assert.Nil(t, cors.AllowedOrigins)
		assert.Nil(t, cors.AllowedMethods)
		assert.Nil(t, cors.AllowedHeaders)
		assert.False(t, cors.AllowCredentials)
	})

	t.Run("complete config", func(t *testing.T) {
		cors := CORSConfig{
			AllowedOrigins:   []string{"https://example.com"},
			AllowedMethods:   []string{"GET", "POST"},
			AllowedHeaders:   []string{"Content-Type"},
			AllowCredentials: true,
		}

		assert.Len(t, cors.AllowedOrigins, 1)
		assert.Len(t, cors.AllowedMethods, 2)
		assert.Len(t, cors.AllowedHeaders, 1)
		assert.True(t, cors.AllowCredentials)
	})

	t.Run("wildcard origin", func(t *testing.T) {
		cors := CORSConfig{
			AllowedOrigins: []string{"*"},
		}

		assert.Contains(t, cors.AllowedOrigins, "*")
	})
}
