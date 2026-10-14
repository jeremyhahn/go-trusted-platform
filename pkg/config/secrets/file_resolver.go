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

package secrets

import (
	"context"
	"log/slog"
	"os"
	"strings"

	quicbaassecret "github.com/jeremyhahn/go-quicbaas/sdk/go/secret"
)

// Compile-time check that FileResolver implements quicbaassecret.SecretResolver.
var _ quicbaassecret.SecretResolver = (*FileResolver)(nil)

const (
	// SchemeFile is the strategy/scheme name for file-backed secrets.
	SchemeFile = "file"

	// SchemeFileURIPrefix is the URI format "file://".
	SchemeFileURIPrefix = "file://"
)

// FileResolver reads a secret value from a path on the local filesystem.
//
// It is a deliberate escape hatch for environments where the KMS-backed
// kms:// resolver is unavailable: Secure Boot airgap provisioning, offline
// development, and recovery flows. The referenced path is read verbatim and
// its raw bytes become the secret value (no base64 decoding, no trimming) so
// the operator stays in full control of the on-disk representation.
//
// URI format: file:///absolute/path/to/secret
//
// Because the value is sourced from plaintext on disk, this resolver is
// opt-in (gated by SecretsConfig.File) and should never be enabled on nodes
// that can reach a KMS.
//
// Thread-safety: This resolver is safe for concurrent use.
type FileResolver struct {
	logger *slog.Logger
}

// NewFileResolver creates a new FileResolver. If logger is nil, a no-op
// logger is used.
func NewFileResolver(logger *slog.Logger) *FileResolver {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &FileResolver{logger: logger}
}

// Scheme returns the URI scheme this resolver handles.
func (r *FileResolver) Scheme() string {
	return SchemeFile
}

// CanResolve returns true if the raw value uses the file:// scheme
// (case-insensitive).
func (r *FileResolver) CanResolve(raw string) bool {
	if raw == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(raw), SchemeFileURIPrefix)
}

// Resolve reads the file referenced by the file:// URI and returns its raw
// bytes as the secret value. The context is checked for cancellation before
// the read so callers can abort long-running config walks.
func (r *FileResolver) Resolve(ctx context.Context, raw string) (*quicbaassecret.SecretValue, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	if !r.CanResolve(raw) {
		return nil, ErrInvalidFileURI{
			Raw:    raw,
			Reason: "does not match file:// scheme",
		}
	}

	path := raw[len(SchemeFileURIPrefix):]
	if path == "" {
		return nil, ErrInvalidFileURI{
			Raw:    raw,
			Reason: "empty path after file:// scheme",
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		r.logger.Error("file secret read failed",
			slog.String("path", path),
			slog.String("error", err.Error()),
		)
		return nil, ErrFileReadFailed{Path: path, Cause: err}
	}

	if len(data) == 0 {
		return nil, ErrFileEmpty{Path: path}
	}

	r.logger.Debug("resolved file secret",
		slog.String("path", path),
		slog.Int("length", len(data)),
	)

	// NewSecretValue seals a copy, so the read buffer is wiped either way.
	defer clear(data)
	return quicbaassecret.NewSecretValue(raw, data, quicbaassecret.StrategyLiteral)
}
