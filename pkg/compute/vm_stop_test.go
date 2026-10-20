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

package compute

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// plainStartStopper is an orchestrator without the VMStopper capability.
type plainStartStopper struct {
	calls []string
}

func (p *plainStartStopper) Start(ctx context.Context, instanceID string) error {
	p.calls = append(p.calls, "start "+instanceID)
	return nil
}

func (p *plainStartStopper) Stop(ctx context.Context, instanceID string) error {
	p.calls = append(p.calls, "stop "+instanceID)
	return nil
}

// optionStopper adds the VMStopper capability and records the options.
type optionStopper struct {
	plainStartStopper
	opts []StopOptions
}

func (o *optionStopper) StopWithOptions(ctx context.Context, instanceID string, opts StopOptions) error {
	o.calls = append(o.calls, "stop "+instanceID)
	o.opts = append(o.opts, opts)
	return nil
}

func TestStopOptionsValidate(t *testing.T) {
	tests := []struct {
		name  string
		opts  StopOptions
		valid bool
	}{
		{name: "default", opts: StopOptions{}, valid: true},
		{name: "force", opts: StopOptions{Force: true}, valid: true},
		{name: "timeout", opts: StopOptions{Timeout: 5 * time.Second}, valid: true},
		{name: "maximum timeout", opts: StopOptions{Timeout: MaxStopTimeout}, valid: true},
		{name: "negative timeout", opts: StopOptions{Timeout: -time.Second}},
		{name: "timeout over the maximum", opts: StopOptions{Timeout: MaxStopTimeout + time.Second}},
		{name: "force with timeout", opts: StopOptions{Force: true, Timeout: time.Second}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if tt.valid {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, ErrInvalidStopOptions)
		})
	}
}

func TestStopOptionsGuestWait(t *testing.T) {
	tests := []struct {
		name string
		opts StopOptions
		want time.Duration
	}{
		{name: "default waits the default window", opts: StopOptions{}, want: DefaultStopTimeout},
		{name: "timeout waits the timeout", opts: StopOptions{Timeout: 5 * time.Second}, want: 5 * time.Second},
		{name: "force does not wait", opts: StopOptions{Force: true}, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.opts.GuestWait())
		})
	}
}

func TestStopWithOptions_UsesVMStopper(t *testing.T) {
	o := &optionStopper{}
	opts := StopOptions{Timeout: 7 * time.Second}

	require.NoError(t, StopWithOptions(context.Background(), o, "vm1", opts))
	assert.Equal(t, []StopOptions{opts}, o.opts)
}

func TestStopWithOptions_PlainOrchestratorTakesDefaultStop(t *testing.T) {
	o := &plainStartStopper{}

	require.NoError(t, StopWithOptions(context.Background(), o, "vm1", StopOptions{}))
	assert.Equal(t, []string{"stop vm1"}, o.calls)
}

func TestStopWithOptions_PlainOrchestratorRefusesOptions(t *testing.T) {
	o := &plainStartStopper{}

	err := StopWithOptions(context.Background(), o, "vm1", StopOptions{Force: true})
	assert.ErrorIs(t, err, ErrUnsupportedOperation)
	assert.Empty(t, o.calls, "a refused stop must not stop the instance")
}

func TestStopWithOptions_InvalidOptionsRefused(t *testing.T) {
	o := &optionStopper{}

	err := StopWithOptions(context.Background(), o, "vm1", StopOptions{Timeout: -time.Second})
	assert.ErrorIs(t, err, ErrInvalidStopOptions)
	assert.Empty(t, o.calls)
}

func TestRebootWithOptions_ForcedStopThenStart(t *testing.T) {
	o := &optionStopper{}

	require.NoError(t, RebootWithOptions(context.Background(), o, "vm1", StopOptions{Force: true}))
	assert.Equal(t, []string{"stop vm1", "start vm1"}, o.calls)
	assert.Equal(t, []StopOptions{{Force: true}}, o.opts)
}

func TestRebootWithOptions_InvalidOptionsNeverStops(t *testing.T) {
	o := &optionStopper{}

	err := RebootWithOptions(context.Background(), o, "vm1", StopOptions{Force: true, Timeout: time.Second})
	assert.ErrorIs(t, err, ErrInvalidStopOptions)
	assert.Empty(t, o.calls)
}

func TestQEMUStopWithOptions_OptionsReachTheProcessStop(t *testing.T) {
	tests := []struct {
		name string
		opts StopOptions
	}{
		{name: "default", opts: StopOptions{}},
		{name: "force", opts: StopOptions{Force: true}},
		{name: "timeout", opts: StopOptions{Timeout: 3 * time.Second}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orch := newOpsOrchestrator(t)
			qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{})
			installRunControlSeam(t, &fakeRunControl{}, nil)
			_, seen := installStopSeamWithOptions(t, orch, qi, nil)

			require.NoError(t, orch.StopWithOptions(context.Background(), "vm1", tt.opts))
			assert.Equal(t, []StopOptions{tt.opts}, *seen)
			assertVMState(t, orch, qi, StateStopped)
		})
	}
}

func TestQEMUStopWithOptions_ForcedStopDoesNotContinueSuspendedVM(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertSuspendedVM(t, orch, "vm1")
	rc := &fakeRunControl{}
	installRunControlSeam(t, rc, nil)
	stops := installStopSeam(t, orch, qi, nil)

	require.NoError(t, orch.StopWithOptions(context.Background(), "vm1", StopOptions{Force: true}))
	assert.Empty(t, rc.commands, "a forced stop kills the paused guest without continuing it")
	assert.Equal(t, 1, *stops)
	assertVMState(t, orch, qi, StateStopped)
}

func TestQEMUStopWithOptions_InvalidOptionsLeaveVMRunning(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{})
	installRunControlSeam(t, &fakeRunControl{}, nil)
	stops := installStopSeam(t, orch, qi, nil)

	err := orch.StopWithOptions(context.Background(), "vm1", StopOptions{Timeout: -time.Second})
	require.ErrorIs(t, err, ErrInvalidStopOptions)
	assert.Equal(t, 0, *stops)
	assertVMState(t, orch, qi, StateRunning)
}
