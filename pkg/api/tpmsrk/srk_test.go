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

package tpmsrk

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// fakeTPM answers only the two accessors this package dispatches to. The
// embedded nil interface means any other call panics rather than passing
// silently, so a change that starts calling something else is loud.
type fakeTPM struct {
	xkmssdk.TrustedPlatformModule

	ssrk    *xkmssdk.KeyAttributes
	ssrkErr error
	psrk    *xkmssdk.KeyAttributes
	psrkErr error
	cfg     *xkmssdk.TPMConfig

	ssrkCalls int
	psrkCalls int
}

func (f *fakeTPM) Config() *xkmssdk.TPMConfig { return f.cfg }

func (f *fakeTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	f.ssrkCalls++
	return f.ssrk, f.ssrkErr
}

func (f *fakeTPM) PlatformSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	f.psrkCalls++
	return f.psrk, f.psrkErr
}

func attrs(cn string, handle uint32) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:            cn,
		TPMAttributes: &xkmssdk.TPMAttributes{Handle: xkmssdk.TPMHandle(handle)},
	}
}

func newFakeTPM() *fakeTPM {
	return &fakeTPM{
		ssrk: attrs("ssrk", SSRKHandle),
		psrk: attrs("platform-srk", PlatformSRKHandle),
	}
}

// TestResolveDispatchesOnTheHandle is the core of #475: each handle must
// reach its own key. Asserting on the CN rather than only the returned
// handle matters, because a transport that ignored the request would
// still return a plausible handle — the SSRK's.
func TestResolveDispatchesOnTheHandle(t *testing.T) {
	cases := map[string]struct {
		handle  uint32
		wantCN  string
		wantSSR int
		wantPSR int
	}{
		"default means SSRK":   {DefaultHandle, "ssrk", 1, 0},
		"explicit SSRK handle": {SSRKHandle, "ssrk", 1, 0},
		"platform SRK handle":  {PlatformSRKHandle, "platform-srk", 0, 1},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tpm := newFakeTPM()

			got, err := Resolve(tpm, tc.handle)
			require.NoError(t, err)
			require.NotNil(t, got)

			assert.Equal(t, tc.wantCN, got.CN,
				"handle 0x%08x resolved to the wrong key", tc.handle)
			assert.Equal(t, tc.wantSSR, tpm.ssrkCalls, "SSRKAttributes call count")
			assert.Equal(t, tc.wantPSR, tpm.psrkCalls, "PlatformSRKAttributes call count")
		})
	}
}

// TestResolveRejectsUnknownHandles is the arm that makes the dispatch
// safe rather than merely correct. A handle naming neither key must be
// an error: falling through to the SSRK would answer with a key the
// caller did not ask for, and report success while doing it.
func TestResolveRejectsUnknownHandles(t *testing.T) {
	for _, handle := range []uint32{
		0x81000000, 0x81000003, 0x81000099, 0x81010001, 0xFFFFFFFF, 1,
	} {
		tpm := newFakeTPM()

		got, err := Resolve(tpm, handle)

		require.Error(t, err, "handle 0x%08x must not resolve", handle)
		assert.Nil(t, got, "no key may be returned for an unknown handle")
		assert.True(t, IsUnknownHandle(err), "expected ErrUnknownHandle, got %T", err)
		assert.Zero(t, tpm.ssrkCalls+tpm.psrkCalls,
			"an unknown handle must not read any key at all")

		var unknown ErrUnknownHandle
		require.True(t, errors.As(err, &unknown))
		assert.Equal(t, handle, unknown.Requested,
			"the error must name the handle the caller asked for")
	}
}

// TestResolveWithoutTPM covers the nil service each transport used to
// guard for itself.
func TestResolveWithoutTPM(t *testing.T) {
	got, err := Resolve(nil, PlatformSRKHandle)

	require.Error(t, err)
	assert.Nil(t, got)
	assert.False(t, IsUnknownHandle(err),
		"an unavailable TPM must not be reported as an unknown handle")
	var unavailable ErrTPMUnavailable
	assert.True(t, errors.As(err, &unavailable))
}

// TestResolvePropagatesAccessorErrors asserts a failure reading the key
// is surfaced as itself, not converted into "unknown handle" — the two
// mean different things to every transport's status mapping.
func TestResolvePropagatesAccessorErrors(t *testing.T) {
	sentinel := errors.New("tpm is in dictionary attack lockout")

	t.Run("ssrk", func(t *testing.T) {
		tpm := newFakeTPM()
		tpm.ssrk, tpm.ssrkErr = nil, sentinel

		_, err := Resolve(tpm, SSRKHandle)
		require.ErrorIs(t, err, sentinel)
		assert.False(t, IsUnknownHandle(err))
	})

	t.Run("platform srk", func(t *testing.T) {
		tpm := newFakeTPM()
		tpm.psrk, tpm.psrkErr = nil, sentinel

		_, err := Resolve(tpm, PlatformSRKHandle)
		require.ErrorIs(t, err, sentinel)
		assert.False(t, IsUnknownHandle(err))
	})
}

// TestUnknownHandleMessageNamesBothKeys keeps the operator-facing text
// useful: the error a caller sees should say what the valid handles are,
// since the whole failure mode is naming the wrong one.
func TestUnknownHandleMessageNamesBothKeys(t *testing.T) {
	msg := ErrUnknownHandle{Requested: 0x81000099}.Error()

	assert.Contains(t, msg, "0x81000099", "names the rejected handle")
	assert.Contains(t, msg, "0x81000001", "names the SSRK handle")
	assert.Contains(t, msg, "0x81000002", "names the PlatformSRK handle")
}

// TestIsUnknownHandleIsSpecific is the positive control for the
// predicate every transport branches on: if it returned true broadly,
// real TPM failures would be mapped to not-found on all four transports.
func TestIsUnknownHandleIsSpecific(t *testing.T) {
	assert.True(t, IsUnknownHandle(ErrUnknownHandle{Requested: 7}))
	assert.False(t, IsUnknownHandle(nil))
	assert.False(t, IsUnknownHandle(ErrTPMUnavailable{}))
	assert.False(t, IsUnknownHandle(errors.New("some other failure")))
}

func configuredTPM(platform, ssrk uint32) *fakeTPM {
	tpm := newFakeTPM()
	tpm.cfg = &xkmssdk.TPMConfig{
		PlatformSRK: &xkmssdk.PlatformSRKConfig{SRKHandle: platform},
		SSRK:        &xkmssdk.SRKConfig{Handle: ssrk},
	}
	return tpm
}

func TestConfiguredHandlesComeFromConfig(t *testing.T) {
	tpm := configuredTPM(0x81000005, 0x81000007)

	assert.Equal(t, uint32(0x81000005), ConfiguredPlatformHandle(tpm))
	assert.Equal(t, uint32(0x81000007), ConfiguredSSRKHandle(tpm))
}

func TestConfiguredHandlesFallBackToDefaults(t *testing.T) {
	cases := map[string]*xkmssdk.TPMConfig{
		"no config":       nil,
		"empty config":    {},
		"zero handles":    {PlatformSRK: &xkmssdk.PlatformSRKConfig{}, SSRK: &xkmssdk.SRKConfig{}},
		"nil sub-configs": {PlatformSRK: nil, SSRK: nil},
	}

	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			tpm := newFakeTPM()
			tpm.cfg = cfg

			assert.Equal(t, PlatformSRKHandle, ConfiguredPlatformHandle(tpm))
			assert.Equal(t, SSRKHandle, ConfiguredSSRKHandle(tpm))
		})
	}
}

func TestInfoPropertiesFormatsConfiguredHandles(t *testing.T) {
	props := InfoProperties(configuredTPM(0x8100000A, 0x81000007))

	assert.Equal(t, map[string]string{
		PropertyPlatformSRKHandle: "0x8100000A",
		PropertySSRKHandle:        "0x81000007",
	}, props)
}

func TestInfoPropertiesFallBackWithoutConfig(t *testing.T) {
	props := InfoProperties(newFakeTPM())

	assert.Equal(t, "0x81000002", props[PropertyPlatformSRKHandle])
	assert.Equal(t, "0x81000001", props[PropertySSRKHandle])
}

func TestResolveAcceptsTheConfiguredHandles(t *testing.T) {
	cases := map[string]struct {
		handle  uint32
		wantCN  string
		wantSSR int
		wantPSR int
	}{
		"configured platform handle": {0x81000005, "platform-srk", 0, 1},
		"configured SSRK handle":     {0x81000007, "ssrk", 1, 0},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tpm := configuredTPM(0x81000005, 0x81000007)

			got, err := Resolve(tpm, tc.handle)
			require.NoError(t, err)

			assert.Equal(t, tc.wantCN, got.CN)
			assert.Equal(t, tc.wantSSR, tpm.ssrkCalls)
			assert.Equal(t, tc.wantPSR, tpm.psrkCalls)
		})
	}
}

func TestResolveRejectsHandlesNotConfigured(t *testing.T) {
	tpm := configuredTPM(0x81000005, 0x81000007)

	got, err := Resolve(tpm, 0x81000006)

	require.Error(t, err)
	assert.Nil(t, got)
	assert.True(t, IsUnknownHandle(err))
	assert.Zero(t, tpm.ssrkCalls+tpm.psrkCalls)
}
