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

package secrets

import "strings"

// ErrRefInvalid is returned when a reference is not a well-formed
// kms:// or secret:// URI. The reference is named because it is a pointer
// to a secret, never the secret.
type ErrRefInvalid struct {
	Ref    string
	Reason string
}

func (e *ErrRefInvalid) Error() string {
	return "secrets: reference " + e.Ref + ": " + e.Reason
}

// ErrSchemeUnsupported is returned when a reference carries a scheme the
// store does not serve. A bare value is refused the same way: the store
// never treats a literal as a secret.
type ErrSchemeUnsupported struct {
	Ref    string
	Scheme string
}

func (e *ErrSchemeUnsupported) Error() string {
	if e.Scheme == "" {
		return "secrets: reference " + e.Ref + ": not a secret reference (expected kms:// or secret://)"
	}
	return "secrets: reference " + e.Ref + ": scheme " + e.Scheme + " is not supported (expected kms:// or secret://)"
}

// ErrStoreUnavailable is returned when the SDK session to the secret store
// cannot be opened. Every consumer fails closed on it.
type ErrStoreUnavailable struct {
	Cause error
}

func (e *ErrStoreUnavailable) Error() string {
	return "secrets: store unavailable: " + e.Cause.Error()
}

func (e *ErrStoreUnavailable) Unwrap() error { return e.Cause }

// ErrSecretUnresolvable is returned when the store cannot return the secret
// behind a reference — it does not exist, the caller is not permitted to
// read it, or the read failed.
type ErrSecretUnresolvable struct {
	Ref   string
	Cause error
}

func (e *ErrSecretUnresolvable) Error() string {
	return "secrets: reference " + e.Ref + ": " + e.Cause.Error()
}

func (e *ErrSecretUnresolvable) Unwrap() error { return e.Cause }

// ErrSecretEmpty is returned when the secret behind a reference resolves to
// no bytes. An empty secret is a fail-open in every consumer (a session
// with no password, a tunnel with a zero key), so it is refused here.
type ErrSecretEmpty struct {
	Ref string
}

func (e *ErrSecretEmpty) Error() string {
	return "secrets: reference " + e.Ref + ": secret is empty"
}

// ErrFieldMissing is returned when the secret holds no field of the
// requested name.
type ErrFieldMissing struct {
	Ref   string
	Field string
}

func (e *ErrFieldMissing) Error() string {
	return "secrets: reference " + e.Ref + ": secret has no field " + e.Field
}

// ErrFieldAmbiguous is returned when a reference names no field and the
// secret holds more than one, so the store cannot know which is the key.
type ErrFieldAmbiguous struct {
	Ref    string
	Fields []string
}

func (e *ErrFieldAmbiguous) Error() string {
	return "secrets: reference " + e.Ref + ": secret has fields " + strings.Join(e.Fields, ", ") + "; name one with #<field>"
}

// ErrFieldNotText is returned when the selected field is not a string. Key
// material travels as text (raw, base64 or hex); a nested object or a
// number is a different kind of secret.
type ErrFieldNotText struct {
	Ref   string
	Field string
}

func (e *ErrFieldNotText) Error() string {
	return "secrets: reference " + e.Ref + ": field " + e.Field + " is not text"
}

// ErrEncodingInvalid is returned when the secret's text does not decode
// under the encoding the reference declares.
type ErrEncodingInvalid struct {
	Ref      string
	Encoding string
	Cause    error
}

func (e *ErrEncodingInvalid) Error() string {
	return "secrets: reference " + e.Ref + ": not valid " + e.Encoding + ": " + e.Cause.Error()
}

func (e *ErrEncodingInvalid) Unwrap() error { return e.Cause }

// ErrConfigInvalid is returned when the secrets: section is malformed.
type ErrConfigInvalid struct {
	Field  string
	Reason string
}

func (e *ErrConfigInvalid) Error() string {
	return "secrets: config " + e.Field + ": " + e.Reason
}

// ErrNilDialFunc is returned when a Store is constructed without a dial
// function.
type ErrNilDialFunc struct{}

func (e *ErrNilDialFunc) Error() string { return "secrets: nil dial function" }

// ErrNilSecretsClient is returned when the SDK client carries no secrets
// service, so there is nothing to read references from.
type ErrNilSecretsClient struct{}

func (e *ErrNilSecretsClient) Error() string {
	return "secrets: the quicbaas SDK client has no secrets service"
}

// ErrTrustRequired is returned when the store is configured but nothing is
// available to authenticate the SDK session: gatewayd has no platform anchor
// (`platform-ca-file:`) to verify the store against.
type ErrTrustRequired struct{}

func (e *ErrTrustRequired) Error() string {
	return "secrets: the platform CA (platform-ca-file:) is required to authenticate the secret store session"
}
