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

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	sdksecrets "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
)

// fakeSession is an in-memory secret store keyed by path.
type fakeSession struct {
	secrets  map[string]*sdksecrets.Secret
	getErr   error
	closeErr error
	gets     []string
	closed   int
}

func (f *fakeSession) Get(_ context.Context, path string) (*sdksecrets.Secret, error) {
	f.gets = append(f.gets, path)
	if f.getErr != nil {
		return nil, f.getErr
	}
	secret, ok := f.secrets[path]
	if !ok {
		return nil, errors.New("not found")
	}
	return secret, nil
}

func (f *fakeSession) Close() error {
	f.closed++
	return f.closeErr
}

func dialTo(session *fakeSession) DialFunc {
	return func(context.Context) (Session, error) { return session, nil }
}

func newTestStore(t *testing.T, session *fakeSession) *Store {
	t.Helper()
	store, err := NewStore(dialTo(session), 0, nil)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

func TestNewStore_RefusesNilDial(t *testing.T) {
	store, err := NewStore(nil, time.Second, nil)
	var want *ErrNilDialFunc
	if !errors.As(err, &want) {
		t.Fatalf("got %v, want ErrNilDialFunc", err)
	}
	if store != nil {
		t.Fatal("expected no store")
	}
}

func TestNewStore_DefaultsTimeout(t *testing.T) {
	store, err := NewStore(dialTo(&fakeSession{}), 0, nil)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if store.timeout != DefaultTimeout {
		t.Fatalf("timeout %v, want %v", store.timeout, DefaultTimeout)
	}
	if store.logger == nil {
		t.Fatal("expected a default logger")
	}
}

func TestResolve_RawPayloadIsTheDataField(t *testing.T) {
	session := &fakeSession{secrets: map[string]*sdksecrets.Secret{
		"platform/bgp/peers/vps-mia/password": {Data: map[string]interface{}{"data": "s3cret"}},
	}}
	store := newTestStore(t, session)

	got, err := store.Resolve(context.Background(), "kms://platform/bgp/peers/vps-mia/password")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != "s3cret" {
		t.Fatalf("got %q, want the raw text", got)
	}
	if len(session.gets) != 1 || session.gets[0] != "platform/bgp/peers/vps-mia/password" {
		t.Fatalf("store read %v, want the path without the scheme", session.gets)
	}
	if session.closed != 1 {
		t.Fatalf("session closed %d times, want 1", session.closed)
	}
}

func TestResolve_SecretSchemeNamesTheSameStore(t *testing.T) {
	session := &fakeSession{secrets: map[string]*sdksecrets.Secret{
		"tunnel/mia/out": {Data: map[string]interface{}{"data": "abc"}},
	}}
	store := newTestStore(t, session)
	got, err := store.Resolve(context.Background(), "secret://tunnel/mia/out")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("got %q", got)
	}
}

func TestResolve_Base64DecodesToKeyBytes(t *testing.T) {
	// 36 bytes: an AES-256-GCM ESP key plus its 4-byte salt.
	session := &fakeSession{secrets: map[string]*sdksecrets.Secret{
		"tunnel/mia/out": {Data: map[string]interface{}{"data": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj\n"}},
	}}
	store := newTestStore(t, session)
	got, err := store.Resolve(context.Background(), "kms://tunnel/mia/out?enc=base64")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 36 || got[0] != 0 || got[35] != 35 {
		t.Fatalf("got %d bytes %v", len(got), got)
	}
}

func TestResolve_HexDecodesToKeyBytes(t *testing.T) {
	session := &fakeSession{secrets: map[string]*sdksecrets.Secret{
		"k": {Data: map[string]interface{}{"data": "deadbeef"}},
	}}
	store := newTestStore(t, session)
	got, err := store.Resolve(context.Background(), "kms://k?enc=hex")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 4 || got[0] != 0xde || got[3] != 0xef {
		t.Fatalf("got %x", got)
	}
}

func TestResolve_FragmentSelectsAJSONField(t *testing.T) {
	session := &fakeSession{secrets: map[string]*sdksecrets.Secret{
		"bgp/peer": {Data: map[string]interface{}{"password": "pw", "note": "ignored"}},
	}}
	store := newTestStore(t, session)
	got, err := store.Resolve(context.Background(), "kms://bgp/peer#password")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != "pw" {
		t.Fatalf("got %q", got)
	}
}

func TestResolve_SingleJSONFieldNeedsNoFragment(t *testing.T) {
	session := &fakeSession{secrets: map[string]*sdksecrets.Secret{
		"bgp/peer": {Data: map[string]interface{}{"password": "pw"}},
	}}
	store := newTestStore(t, session)
	got, err := store.Resolve(context.Background(), "kms://bgp/peer")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != "pw" {
		t.Fatalf("got %q", got)
	}
}

func TestResolve_ReturnsACallerOwnedCopy(t *testing.T) {
	session := &fakeSession{secrets: map[string]*sdksecrets.Secret{
		"k": {Data: map[string]interface{}{"data": "abc"}},
	}}
	store := newTestStore(t, session)
	first, err := store.Resolve(context.Background(), "kms://k")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	Zeroize(first)
	second, err := store.Resolve(context.Background(), "kms://k")
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if string(second) != "abc" {
		t.Fatalf("zeroizing the first copy changed the second: %q", second)
	}
}

func TestResolve_FailsClosed(t *testing.T) {
	boom := errors.New("boom")
	// One predicate per refusal the store can report, so the table below
	// reads as the refusal it expects.
	refInvalid := func(err error) bool { var e *ErrRefInvalid; return errors.As(err, &e) }
	schemeUnsupported := func(err error) bool { var e *ErrSchemeUnsupported; return errors.As(err, &e) }
	storeUnavailable := func(err error) bool { var e *ErrStoreUnavailable; return errors.As(err, &e) }
	unresolvable := func(err error) bool { var e *ErrSecretUnresolvable; return errors.As(err, &e) }
	empty := func(err error) bool { var e *ErrSecretEmpty; return errors.As(err, &e) }
	ambiguous := func(err error) bool { var e *ErrFieldAmbiguous; return errors.As(err, &e) }
	fieldMissing := func(err error) bool { var e *ErrFieldMissing; return errors.As(err, &e) }
	notText := func(err error) bool { var e *ErrFieldNotText; return errors.As(err, &e) }
	badEncoding := func(err error) bool { var e *ErrEncodingInvalid; return errors.As(err, &e) }
	cases := []struct {
		name    string
		ref     string
		session *fakeSession
		dial    DialFunc
		want    func(error) bool
		wantMsg string
		reads   int
	}{
		{name: "empty ref", ref: "", session: &fakeSession{}, want: refInvalid, wantMsg: "ErrRefInvalid"},
		{name: "bare value is not a reference", ref: "hunter2", session: &fakeSession{}, want: schemeUnsupported, wantMsg: "ErrSchemeUnsupported"},
		{name: "unsupported scheme", ref: "env://X", session: &fakeSession{}, want: schemeUnsupported, wantMsg: "ErrSchemeUnsupported"},
		{name: "file scheme refused", ref: "file:///etc/key", session: &fakeSession{}, want: schemeUnsupported, wantMsg: "ErrSchemeUnsupported"},
		{name: "empty path", ref: "kms://", session: &fakeSession{}, want: refInvalid, wantMsg: "ErrRefInvalid"},
		{name: "empty path with options", ref: "kms://?enc=hex", session: &fakeSession{}, want: refInvalid, wantMsg: "ErrRefInvalid"},
		{name: "empty fragment", ref: "kms://k#", session: &fakeSession{}, want: refInvalid, wantMsg: "ErrRefInvalid"},
		{name: "ensure is refused", ref: "kms://k?ensure=true", session: &fakeSession{}, want: refInvalid, wantMsg: "ErrRefInvalid"},
		{name: "unknown encoding", ref: "kms://k?enc=rot13", session: &fakeSession{}, want: refInvalid, wantMsg: "ErrRefInvalid"},
		{name: "enc twice", ref: "kms://k?enc=hex&enc=raw", session: &fakeSession{}, want: refInvalid, wantMsg: "ErrRefInvalid"},
		{name: "malformed query", ref: "kms://k?enc=%zz", session: &fakeSession{}, want: refInvalid, wantMsg: "ErrRefInvalid"},
		{name: "dial failure", ref: "kms://k", dial: func(context.Context) (Session, error) { return nil, boom }, want: storeUnavailable, wantMsg: "ErrStoreUnavailable"},
		{name: "read failure", ref: "kms://k", session: &fakeSession{getErr: boom}, want: unresolvable, wantMsg: "ErrSecretUnresolvable", reads: 1},
		{name: "missing secret", ref: "kms://missing", session: &fakeSession{}, want: unresolvable, wantMsg: "ErrSecretUnresolvable", reads: 1},
		{name: "empty secret", ref: "kms://k", session: &fakeSession{secrets: map[string]*sdksecrets.Secret{"k": {Data: map[string]interface{}{}}}}, want: empty, wantMsg: "ErrSecretEmpty", reads: 1},
		{name: "empty text", ref: "kms://k", session: &fakeSession{secrets: map[string]*sdksecrets.Secret{"k": {Data: map[string]interface{}{"data": ""}}}}, want: empty, wantMsg: "ErrSecretEmpty", reads: 1},
		{name: "ambiguous fields", ref: "kms://k", session: &fakeSession{secrets: map[string]*sdksecrets.Secret{"k": {Data: map[string]interface{}{"a": "1", "b": "2"}}}}, want: ambiguous, wantMsg: "ErrFieldAmbiguous", reads: 1},
		{name: "missing field", ref: "kms://k#nope", session: &fakeSession{secrets: map[string]*sdksecrets.Secret{"k": {Data: map[string]interface{}{"a": "1"}}}}, want: fieldMissing, wantMsg: "ErrFieldMissing", reads: 1},
		{name: "field not text", ref: "kms://k#n", session: &fakeSession{secrets: map[string]*sdksecrets.Secret{"k": {Data: map[string]interface{}{"n": 42}}}}, want: notText, wantMsg: "ErrFieldNotText", reads: 1},
		{name: "bad base64", ref: "kms://k?enc=base64", session: &fakeSession{secrets: map[string]*sdksecrets.Secret{"k": {Data: map[string]interface{}{"data": "!!!"}}}}, want: badEncoding, wantMsg: "ErrEncodingInvalid", reads: 1},
		{name: "bad hex", ref: "kms://k?enc=hex", session: &fakeSession{secrets: map[string]*sdksecrets.Secret{"k": {Data: map[string]interface{}{"data": "xyz"}}}}, want: badEncoding, wantMsg: "ErrEncodingInvalid", reads: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dial := tc.dial
			if dial == nil {
				dial = dialTo(tc.session)
			}
			store, err := NewStore(dial, time.Second, nil)
			if err != nil {
				t.Fatalf("NewStore: %v", err)
			}
			got, err := store.Resolve(context.Background(), tc.ref)
			if got != nil {
				t.Fatalf("expected no material, got %d bytes", len(got))
			}
			if err == nil {
				t.Fatal("expected an error")
			}
			if !tc.want(err) {
				t.Fatalf("got %T (%v), want %s", err, err, tc.wantMsg)
			}
			if tc.session != nil && len(tc.session.gets) != tc.reads {
				t.Fatalf("store read %d times, want %d", len(tc.session.gets), tc.reads)
			}
			if tc.session != nil && tc.reads > 0 && tc.session.closed != 1 {
				t.Fatalf("session closed %d times after a read, want 1", tc.session.closed)
			}
		})
	}
}

func TestResolve_ErrorsNameTheReferenceNotTheMaterial(t *testing.T) {
	session := &fakeSession{secrets: map[string]*sdksecrets.Secret{
		"k": {Data: map[string]interface{}{"data": "not-base64-material"}},
	}}
	store := newTestStore(t, session)
	_, err := store.Resolve(context.Background(), "kms://k?enc=base64")
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "kms://k?enc=base64") {
		t.Fatalf("error should name the reference: %s", msg)
	}
	if strings.Contains(msg, "not-base64-material") {
		t.Fatalf("error leaks the material: %s", msg)
	}
}

func TestResolve_CloseFailureDoesNotRefuseTheKey(t *testing.T) {
	session := &fakeSession{
		secrets:  map[string]*sdksecrets.Secret{"k": {Data: map[string]interface{}{"data": "v"}}},
		closeErr: errors.New("close failed"),
	}
	store := newTestStore(t, session)
	got, err := store.Resolve(context.Background(), "kms://k")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != "v" {
		t.Fatalf("got %q", got)
	}
}

func TestResolve_HonoursTheTimeout(t *testing.T) {
	dial := func(ctx context.Context) (Session, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, errors.New("no deadline on the dial context")
		}
		if time.Until(deadline) > 50*time.Millisecond {
			return nil, errors.New("deadline further than the configured timeout")
		}
		return &fakeSession{secrets: map[string]*sdksecrets.Secret{"k": {Data: map[string]interface{}{"data": "v"}}}}, nil
	}
	store, err := NewStore(dial, 50*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if _, err := store.Resolve(context.Background(), "kms://k"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
}

func TestZeroize_OverwritesEveryByte(t *testing.T) {
	b := []byte{1, 2, 3}
	Zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d is %d", i, v)
		}
	}
	Zeroize(nil)
}

func TestParseRef_Parts(t *testing.T) {
	got, err := parseRef("secret://a/b/c?enc=hex#key")
	if err != nil {
		t.Fatalf("parseRef: %v", err)
	}
	if got.scheme != SchemeSecret || got.path != "a/b/c" || got.encoding != EncodingHex || got.field != "key" {
		t.Fatalf("parsed %+v", got)
	}
}

func TestParseRef_RefusesSchemeInMixedCase(t *testing.T) {
	if _, err := parseRef("KMS://a"); err == nil {
		t.Fatal("expected an error")
	}
}
