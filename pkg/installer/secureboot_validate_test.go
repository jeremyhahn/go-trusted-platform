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

package installer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecureBootConfigValidate exercises the URI-driven Secure Boot validation
// rules: disabled/nil short-circuits, a DB key URI is mandatory, enforce
// promotes PK+KEK to mandatory, and only kms:// or file:// URI schemes are
// accepted (case-insensitively).
func TestSecureBootConfigValidate(t *testing.T) {
	tests := []struct {
		name     string
		config   *SecureBootConfig
		wantErr  bool
		errField string
	}{
		{
			name:    "nil config returns nil",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "disabled returns nil even when otherwise empty",
			config:  &SecureBootConfig{Enabled: false},
			wantErr: false,
		},
		{
			name: "valid kms happy path",
			config: &SecureBootConfig{
				Enabled:    true,
				ResignMode: SecureBootResignModeRemote,
				DB:         SecureBootKeyRef{KeyURI: "kms://platform/secureboot/db"},
			},
			wantErr: false,
		},
		{
			name: "missing db key uri",
			config: &SecureBootConfig{
				Enabled:    true,
				ResignMode: SecureBootResignModeRemote,
			},
			wantErr:  true,
			errField: "db.key-uri",
		},
		{
			name: "invalid resign mode",
			config: &SecureBootConfig{
				Enabled:    true,
				ResignMode: "carrier-pigeon",
				DB:         SecureBootKeyRef{KeyURI: "kms://platform/secureboot/db"},
			},
			wantErr:  true,
			errField: "resign-mode",
		},
		{
			name: "bad db key uri scheme",
			config: &SecureBootConfig{
				Enabled:    true,
				ResignMode: SecureBootResignModeLocal,
				DB:         SecureBootKeyRef{KeyURI: "https://evil.example/db"},
			},
			wantErr:  true,
			errField: "db.key-uri",
		},
		{
			name: "bad db cert uri scheme",
			config: &SecureBootConfig{
				Enabled:    true,
				ResignMode: SecureBootResignModeLocal,
				DB: SecureBootKeyRef{
					KeyURI:  "kms://platform/secureboot/db",
					CertURI: "ftp://platform/secureboot/db-cert",
				},
			},
			wantErr:  true,
			errField: "db.cert-uri",
		},
		{
			name: "enforce without pk",
			config: &SecureBootConfig{
				Enabled:    true,
				Enforce:    true,
				ResignMode: SecureBootResignModeRemote,
				KEK:        SecureBootKeyRef{KeyURI: "kms://platform/secureboot/kek"},
				DB:         SecureBootKeyRef{KeyURI: "kms://platform/secureboot/db"},
			},
			wantErr:  true,
			errField: "pk.key-uri",
		},
		{
			name: "enforce without kek",
			config: &SecureBootConfig{
				Enabled:    true,
				Enforce:    true,
				ResignMode: SecureBootResignModeRemote,
				PK:         SecureBootKeyRef{KeyURI: "kms://platform/secureboot/pk"},
				DB:         SecureBootKeyRef{KeyURI: "kms://platform/secureboot/db"},
			},
			wantErr:  true,
			errField: "kek.key-uri",
		},
		{
			name: "enforce happy path with case-insensitive schemes",
			config: &SecureBootConfig{
				Enabled:    true,
				Enforce:    true,
				ResignMode: SecureBootResignModeRemote,
				PK:         SecureBootKeyRef{KeyURI: "file:///etc/secureboot/PK.key"},
				KEK:        SecureBootKeyRef{KeyURI: "FILE:///etc/secureboot/KEK.key"},
				DB:         SecureBootKeyRef{KeyURI: "KMS://platform/secureboot/db"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if !tt.wantErr {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			var sbErr *ErrSecureBootConfig
			require.ErrorAs(t, err, &sbErr)
			assert.Equal(t, tt.errField, sbErr.Field)
		})
	}
}

// TestSecureBootConfigValidate_DefaultsResignMode verifies that an empty
// ResignMode is defaulted to "remote" in place when the config is otherwise
// valid, so callers can rely on a populated mode after Validate succeeds.
func TestSecureBootConfigValidate_DefaultsResignMode(t *testing.T) {
	cfg := &SecureBootConfig{
		Enabled: true,
		DB:      SecureBootKeyRef{KeyURI: "kms://platform/secureboot/db"},
	}
	require.NoError(t, cfg.Validate())
	assert.Equal(t, SecureBootResignModeRemote, cfg.ResignMode)
}
