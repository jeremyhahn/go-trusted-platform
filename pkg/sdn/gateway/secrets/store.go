// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package secrets resolves the secret references gatewayd's configuration
// carries — BGP neighbour passwords, TCP-AO master keys, IPsec and
// WireGuard tunnel keys — through the platform secret store (quicbaasd's
// KMS secrets service, owner ruling R10). Configuration holds references,
// never values (handbook configuration.md §4): a reference is resolved at
// service start, the material is handed to exactly one consumer, and that
// consumer zeroizes it once the kernel or the speaker holds it.
//
// A reference is
//
//	kms://<path>[?enc=raw|base64|hex][#<field>]
//	secret://<path>[?enc=raw|base64|hex][#<field>]
//
// Both schemes name the same store; kms:// is the platform-wide spelling
// (the one platformd's own configuration uses), secret:// reads better for
// an operator who thinks of the value as a stored secret. <path> is the
// secret's path as `platformctl secrets` shows it. A secret stored as a
// plain payload is one field named "data"; a JSON payload is one field per
// key. Without #<field> the secret must hold exactly one field. enc says
// how the field's text encodes the bytes the consumer needs: raw (the
// text's bytes, the default — a BGP password), base64 (a 36-byte ESP key
// minted with `?ensure=true&enc=base64`) or hex.
//
// The store fails closed on every path: a bare value is not a reference,
// an unsupported scheme or option is refused, an empty secret is refused,
// and an unreachable store stops the service that needed the key. Errors
// name the reference and never the material.
package secrets

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	sdksecrets "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
)

// Schemes the store serves.
const (
	SchemeKMS    = "kms"
	SchemeSecret = "secret"
)

// Encodings a reference may declare with ?enc=.
const (
	EncodingRaw    = "raw"
	EncodingBase64 = "base64"
	EncodingHex    = "hex"
)

// Session is one open connection to the secret store. The production
// session wraps a go-quicbaas SDK client; tests inject fakes.
type Session interface {
	// Get reads the secret at path.
	Get(ctx context.Context, path string) (*sdksecrets.Secret, error)
	// Close releases the connection.
	Close() error
}

// DialFunc opens a Session. The store dials per resolution and closes the
// session afterwards: resolutions happen at service start and rekey, and
// an idle connection to the key store is nothing to keep.
type DialFunc func(ctx context.Context) (Session, error)

// Store resolves references through the platform secret store. Its
// Resolve method has the shape of bgp.SecretResolver; the gateway adapts
// the same method for tunnel.KeyProvider, so one store serves both.
type Store struct {
	dial    DialFunc
	timeout time.Duration
	logger  *slog.Logger
}

// NewStore builds a Store around dial. A non-positive timeout means
// DefaultTimeout; a nil logger means slog.Default.
func NewStore(dial DialFunc, timeout time.Duration, logger *slog.Logger) (*Store, error) {
	if dial == nil {
		return nil, &ErrNilDialFunc{}
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Store{dial: dial, timeout: timeout, logger: logger}, nil
}

// Resolve returns the material behind ref. The returned slice is a fresh
// allocation owned by the caller, who zeroizes it after hand-off.
func (s *Store) Resolve(ctx context.Context, ref string) ([]byte, error) {
	parsed, err := parseRef(ref)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	session, err := s.dial(ctx)
	if err != nil {
		return nil, &ErrStoreUnavailable{Cause: err}
	}
	defer func() {
		// The read has already succeeded or failed by the time the session
		// closes; a close failure is worth a log line, not a refused key.
		if cerr := session.Close(); cerr != nil {
			s.logger.Warn("secrets: closing the store session failed", slog.Any("error", cerr))
		}
	}()

	secret, err := session.Get(ctx, parsed.path)
	if err != nil {
		return nil, &ErrSecretUnresolvable{Ref: ref, Cause: err}
	}
	if secret == nil {
		return nil, &ErrSecretEmpty{Ref: ref}
	}
	text, err := selectField(ref, parsed.field, secret.Data)
	if err != nil {
		return nil, err
	}
	return decode(ref, parsed.encoding, text)
}

// reference is a parsed kms:// or secret:// URI.
type reference struct {
	scheme   string
	path     string
	field    string
	encoding string
}

// parseRef splits ref into its parts and refuses everything the store does
// not serve.
func parseRef(ref string) (*reference, error) {
	if ref == "" {
		return nil, &ErrRefInvalid{Ref: ref, Reason: "empty reference"}
	}
	schemeEnd := strings.Index(ref, "://")
	if schemeEnd < 0 {
		return nil, &ErrSchemeUnsupported{Ref: ref}
	}
	scheme := ref[:schemeEnd]
	if scheme != SchemeKMS && scheme != SchemeSecret {
		return nil, &ErrSchemeUnsupported{Ref: ref, Scheme: scheme}
	}
	rest := ref[schemeEnd+len("://"):]
	out := &reference{scheme: scheme, encoding: EncodingRaw}

	if i := strings.IndexByte(rest, '#'); i >= 0 {
		out.field = rest[i+1:]
		rest = rest[:i]
		if out.field == "" {
			return nil, &ErrRefInvalid{Ref: ref, Reason: "empty #field"}
		}
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		query, err := url.ParseQuery(rest[i+1:])
		if err != nil {
			return nil, &ErrRefInvalid{Ref: ref, Reason: "malformed query"}
		}
		rest = rest[:i]
		for key, values := range query {
			if key != "enc" {
				return nil, &ErrRefInvalid{Ref: ref, Reason: "unsupported option " + key + " (the gateway never mints its own keys; only enc= is accepted)"}
			}
			if len(values) != 1 {
				return nil, &ErrRefInvalid{Ref: ref, Reason: "enc given more than once"}
			}
			switch values[0] {
			case EncodingRaw, EncodingBase64, EncodingHex:
				out.encoding = values[0]
			default:
				return nil, &ErrRefInvalid{Ref: ref, Reason: "enc must be raw, base64 or hex"}
			}
		}
	}
	if rest == "" {
		return nil, &ErrRefInvalid{Ref: ref, Reason: "empty path"}
	}
	out.path = rest
	return out, nil
}

// selectField picks the field the reference names, or the only field the
// secret has.
func selectField(ref, field string, data map[string]interface{}) (string, error) {
	if field == "" {
		switch len(data) {
		case 0:
			return "", &ErrSecretEmpty{Ref: ref}
		case 1:
			for name := range data {
				field = name
			}
		default:
			names := make([]string, 0, len(data))
			for name := range data {
				names = append(names, name)
			}
			sort.Strings(names)
			return "", &ErrFieldAmbiguous{Ref: ref, Fields: names}
		}
	}
	value, ok := data[field]
	if !ok {
		return "", &ErrFieldMissing{Ref: ref, Field: field}
	}
	text, ok := value.(string)
	if !ok {
		return "", &ErrFieldNotText{Ref: ref, Field: field}
	}
	return text, nil
}

// decode turns the field's text into the bytes the consumer needs. An
// empty result is refused: no consumer has a use for a zero-length key.
func decode(ref, encoding, text string) ([]byte, error) {
	var (
		out []byte
		err error
	)
	switch encoding {
	case EncodingBase64:
		out, err = base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	case EncodingHex:
		out, err = hex.DecodeString(strings.TrimSpace(text))
	default:
		out = []byte(text)
	}
	if err != nil {
		return nil, &ErrEncodingInvalid{Ref: ref, Encoding: encoding, Cause: err}
	}
	if len(out) == 0 {
		return nil, &ErrSecretEmpty{Ref: ref}
	}
	return out, nil
}

// Zeroize overwrites b in place. Consumers call it once the material has
// been handed to the kernel or the speaker.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
