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

package credentials

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// SecretsService is the narrow subset of the QuicBaaS SecretsService
// that QuicBaaSStore needs. Defined here so tests can substitute a
// minimal fake without pulling in the full QuicBaaS server surface.
type SecretsService interface {
	StoreSecret(ctx context.Context, req *baasservice.StoreSecretRequest) (*baasservice.StoreSecretResponse, error)
	GetSecret(ctx context.Context, req *baasservice.GetSecretRequest) (*baasservice.GetSecretResponse, error)
	DeleteSecret(ctx context.Context, req *baasservice.DeleteSecretRequest) (*baasservice.DeleteSecretResponse, error)
	ListSecrets(ctx context.Context, req *baasservice.ListSecretsRequest) (*baasservice.ListSecretsResponse, error)
	RotateSecret(ctx context.Context, req *baasservice.RotateSecretRequest) (*baasservice.RotateSecretResponse, error)
	ListSecretVersions(ctx context.Context, req *baasservice.ListSecretVersionsRequest) (*baasservice.ListSecretVersionsResponse, error)
}

// Compile-time assertion that baasservice.SecretsService satisfies the
// narrowed interface. If upstream removes any of these methods the
// project won't compile here, flagging the breakage early.
var _ SecretsService = (baasservice.SecretsService)(nil)

// QuicBaaSStore is a bmc.CredentialStore backed by the QuicBaaS
// SecretsService. Each BMC credential is persisted at path
// bmc.CredentialPath(name) with the Credentials value JSON-serialized
// into Secret.Data. Encryption at rest is provided by the underlying
// service.
type QuicBaaSStore struct {
	svc SecretsService
}

// Compile-time interface check.
var _ bmc.CredentialStore = (*QuicBaaSStore)(nil)

// NewQuicBaaSStore wraps svc in a bmc.CredentialStore. svc must be
// non-nil.
func NewQuicBaaSStore(svc SecretsService) (*QuicBaaSStore, error) {
	if svc == nil {
		return nil, bmc.ErrInvalidCredentials{Reason: "nil SecretsService"}
	}
	return &QuicBaaSStore{svc: svc}, nil
}

// Get retrieves the credentials stored at bmc.CredentialPath(name).
func (s *QuicBaaSStore) Get(ctx context.Context, name string) (*bmc.Credentials, error) {
	if name == "" {
		return nil, bmc.ErrInvalidCredentials{Reason: "empty name"}
	}
	resp, err := s.svc.GetSecret(ctx, &baasservice.GetSecretRequest{
		SecretID: bmc.CredentialPath(name),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, bmc.ErrCredentialsNotFound{Name: name}
		}
		return nil, err
	}
	if len(resp.Data) == 0 {
		return nil, bmc.ErrCredentialsNotFound{Name: name}
	}
	// UnmarshalCredentials zeros its input, including resp.Data below.
	// Copy so we don't corrupt the caller's response struct.
	buf := append([]byte(nil), resp.Data...)
	return bmc.UnmarshalCredentials(buf)
}

// Put stores credentials at bmc.CredentialPath(name). If the credential
// already exists, a new version is created via RotateSecret. For new
// credentials, StoreSecret is used to create the initial version.
// After return, the marshaled bytes are scrubbed from memory.
func (s *QuicBaaSStore) Put(ctx context.Context, name string, creds *bmc.Credentials) error {
	if name == "" {
		return bmc.ErrInvalidCredentials{Reason: "empty name"}
	}
	if creds == nil || !creds.IsAlive() {
		return bmc.ErrInvalidCredentials{Reason: "credentials are nil or destroyed"}
	}
	blob, err := bmc.MarshalCredentials(creds)
	if err != nil {
		return err
	}
	defer zeroBytes(blob)

	path := bmc.CredentialPath(name)

	// Try RotateSecret first. If the secret does not exist yet,
	// fall back to StoreSecret for the initial version.
	_, err = s.svc.RotateSecret(ctx, &baasservice.RotateSecretRequest{
		SecretID: path,
		NewData:  blob,
		Metadata: map[string]string{
			"username": creds.Username,
			"rotated":  time.Now().UTC().Format(time.RFC3339),
		},
	})
	if err != nil {
		if isNotFound(err) {
			_, err = s.svc.StoreSecret(ctx, &baasservice.StoreSecretRequest{
				SecretID: path,
				Name:     path,
				Data:     blob,
			})
		}
	}
	return err
}

// Delete soft-deletes the current version of credentials at
// bmc.CredentialPath(name). Previous versions are preserved for audit
// history. Not found is reported as a successful no-op.
func (s *QuicBaaSStore) Delete(ctx context.Context, name string) error {
	if name == "" {
		return bmc.ErrInvalidCredentials{Reason: "empty name"}
	}
	_, err := s.svc.DeleteSecret(ctx, &baasservice.DeleteSecretRequest{
		SecretID:          bmc.CredentialPath(name),
		PermanentlyDelete: false,
		AllVersions:       false,
	})
	if err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

// List enumerates the names of all stored BMC credentials under the
// bmc.CredentialPrefix.
func (s *QuicBaaSStore) List(ctx context.Context) ([]string, error) {
	resp, err := s.svc.ListSecrets(ctx, &baasservice.ListSecretsRequest{
		Prefix: bmc.CredentialPrefix,
	})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(resp.Secrets))
	for _, sec := range resp.Secrets {
		if sec == nil {
			continue
		}
		id := secretID(sec)
		if !strings.HasPrefix(id, bmc.CredentialPrefix) {
			continue
		}
		name := bmc.NameFromCredentialPath(id)
		if name != "" {
			out = append(out, name)
		}
	}
	return out, nil
}

// History returns ordered credential versions (newest first) for audit.
// Returns empty slice if the credential has no history.
func (s *QuicBaaSStore) History(ctx context.Context, name string) ([]bmc.CredentialVersion, error) {
	if name == "" {
		return nil, bmc.ErrInvalidCredentials{Reason: "empty name"}
	}
	resp, err := s.svc.ListSecretVersions(ctx, &baasservice.ListSecretVersionsRequest{
		SecretID: bmc.CredentialPath(name),
	})
	if err != nil {
		if isNotFound(err) {
			return []bmc.CredentialVersion{}, nil
		}
		return nil, err
	}
	out := make([]bmc.CredentialVersion, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		if v == nil {
			continue
		}
		out = append(out, bmc.CredentialVersion{
			Version:   v.Version,
			CreatedAt: v.CreatedAt,
		})
	}
	// Sort newest first by version descending.
	sort.Slice(out, func(i, j int) bool {
		return out[i].Version > out[j].Version
	})
	return out, nil
}

// secretID extracts the path identity from a baasservice.Secret.
// Prefers SecretID (the stable key) and falls back to Name.
func secretID(sec *baasservice.Secret) string {
	if sec == nil {
		return ""
	}
	if sec.SecretID != "" {
		return sec.SecretID
	}
	return sec.Name
}

// isNotFound reports whether err represents a secret-not-found
// condition at the QuicBaaS service layer. QuicBaaS error wrapping
// loses type information across transports; fall back to string
// matching when unwrapping fails. This pattern is documented in
// MEMORY.md under "Not-found error wrapping".
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	// Typed check (best case).
	if errors.Is(err, errNotFoundSentinel) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"not found", "no such secret", "does not exist", "404",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// errNotFoundSentinel is a local sentinel used only for errors.Is
// inspection. It will never match unless an upstream layer explicitly
// wraps it; in that case, prefer the typed path.
var errNotFoundSentinel = errors.New("quicbaas: not found")

// zeroBytes wipes b. Best-effort; compiler may elide if b is
// otherwise unreachable.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
