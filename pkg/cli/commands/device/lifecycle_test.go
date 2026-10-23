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

package device

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeLifecycleClient records the transition it was asked for and answers
// with resp or err.
type fakeLifecycleClient struct {
	resp *platformv1.DeviceLifecycleResponse
	err  error

	called string
	id     uint64
	reason string
}

func (f *fakeLifecycleClient) Disable(_ context.Context, id uint64, reason string) (*platformv1.DeviceLifecycleResponse, error) {
	f.called, f.id, f.reason = "disable", id, reason
	return f.resp, f.err
}

func (f *fakeLifecycleClient) Enable(_ context.Context, id uint64) (*platformv1.DeviceLifecycleResponse, error) {
	f.called, f.id = "enable", id
	return f.resp, f.err
}

func TestApplyDeviceLifecycle_Disable(t *testing.T) {
	client := &fakeLifecycleClient{resp: &platformv1.DeviceLifecycleResponse{
		DeviceId: 7, State: "suspended", PreviousState: "attested", StateReason: "operator: rma pending",
	}}

	out, err := applyDeviceLifecycle(context.Background(), client, 7, false, "rma pending")
	require.NoError(t, err)

	assert.Equal(t, "disable", client.called)
	assert.Equal(t, uint64(7), client.id)
	assert.Equal(t, "rma pending", client.reason, "the reason reaches the control plane")
	assert.Equal(t, lifecycleOutput{
		ID: 7, State: "suspended", PreviousState: "attested", StateReason: "operator: rma pending",
	}, out)
}

func TestApplyDeviceLifecycle_Enable(t *testing.T) {
	client := &fakeLifecycleClient{resp: &platformv1.DeviceLifecycleResponse{
		DeviceId: 7, State: "quarantined", PreviousState: "suspended", ReattestationRequested: true,
	}}

	out, err := applyDeviceLifecycle(context.Background(), client, 7, true, "")
	require.NoError(t, err)

	assert.Equal(t, "enable", client.called, "enable never calls disable")
	assert.Equal(t, "quarantined", out.State)
	assert.True(t, out.ReattestationRequested)
}

func TestApplyDeviceLifecycle_WrapsTheRefusal(t *testing.T) {
	refusal := errors.New("device 7 has no network port on record")

	_, err := applyDeviceLifecycle(context.Background(), &fakeLifecycleClient{err: refusal}, 7, false, "")
	var disableErr ErrDisableDeviceFailed
	require.True(t, errors.As(err, &disableErr), "err = %v, want ErrDisableDeviceFailed", err)
	assert.Equal(t, uint64(7), disableErr.ID)
	assert.Contains(t, err.Error(), refusal.Error(), "the server's reason is shown")

	_, err = applyDeviceLifecycle(context.Background(), &fakeLifecycleClient{err: refusal}, 7, true, "")
	var enableErr ErrEnableDeviceFailed
	require.True(t, errors.As(err, &enableErr), "err = %v, want ErrEnableDeviceFailed", err)
	assert.Contains(t, err.Error(), "not enabled")
}

func TestRunDeviceLifecycle_RejectsAnInvalidID(t *testing.T) {
	for _, enable := range []bool{false, true} {
		for _, id := range []string{"0", "abc", "-1", ""} {
			err := runDeviceLifecycle(&cli.CommonFlags{}, id, enable, "")
			var invalid ErrInvalidDeviceID
			require.True(t, errors.As(err, &invalid), "enable=%v id %q: err = %v, want ErrInvalidDeviceID", enable, id, err)
			assert.Equal(t, id, invalid.ID)
		}
	}
}

func TestDeviceLifecycleCommands_Shape(t *testing.T) {
	getFlags := func() *cli.CommonFlags { return &cli.CommonFlags{} }

	disable := newDisableCommand(getFlags)
	reason := disable.Flags().Lookup("reason")
	require.NotNil(t, reason, "disable takes --reason")
	assert.Equal(t, "", reason.DefValue)
	assert.Error(t, disable.Args(disable, nil), "disable needs a device id")

	enable := newEnableCommand(getFlags)
	assert.Nil(t, enable.Flags().Lookup("reason"), "enable takes no reason")
	assert.Error(t, enable.Args(enable, []string{"1", "2"}), "enable takes exactly one device id")

	root := NewCommand(getFlags)
	for _, name := range []string{"disable", "enable"} {
		sub, _, err := root.Find([]string{name})
		require.NoError(t, err)
		assert.Equal(t, name, sub.Name(), "device %s is registered", name)
	}
}

func TestPrintDeviceLifecycle(t *testing.T) {
	t.Run("disable", func(t *testing.T) {
		var buf bytes.Buffer
		printDeviceLifecycle(cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf), lifecycleOutput{
			ID: 7, State: "suspended", PreviousState: "attested", StateReason: "operator: rma pending",
		}, false)

		out := buf.String()
		assert.Contains(t, out, "Device disabled")
		assert.Contains(t, out, "operator: rma pending")
		assert.NotContains(t, out, "Re-attestation", "a disable requests no re-attestation")
	})
	t.Run("enable", func(t *testing.T) {
		var buf bytes.Buffer
		printDeviceLifecycle(cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf), lifecycleOutput{
			ID: 7, State: "quarantined", PreviousState: "suspended", ReattestationRequested: true,
		}, true)

		out := buf.String()
		assert.Contains(t, out, "quarantined until it re-attests", "the operator learns the device is not yet restored")
		assert.Contains(t, out, "Re-attestation Requested")
		assert.NotContains(t, out, "Reason", "an empty reason is not printed")
	})
}
