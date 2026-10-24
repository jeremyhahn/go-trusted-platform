package bootstrap

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// powerTestOrchestrator returns an orchestrator whose poll loops run on
// queued ticks instead of real intervals.
func powerTestOrchestrator(factory bmc.ClientFactory) *Orchestrator {
	return &Orchestrator{
		logger:     orchTestLogger(),
		bmcFactory: factory,
		pollTicker: newFakeHealthTicker(2 * powerVerifyRetries).New,
	}
}

func TestVerifyPowerOn(t *testing.T) {
	errBMC := errors.New("bmc unreachable")

	tests := []struct {
		name            string
		power           bmc.PowerState
		powerOnErr      error
		powerStatusErr  error
		wantOn          bool
		wantState       bmc.PowerState
		wantStatusCalls int64
		wantPowerOns    int64
	}{
		{
			// Three consecutive off polls re-issue PowerOn; the next
			// poll sees the host on.
			name:            "stuck-off host is powered on again",
			power:           bmc.PowerStateOff,
			wantOn:          true,
			wantState:       bmc.PowerStateOn,
			wantStatusCalls: 4,
			wantPowerOns:    1,
		},
		{
			// PowerOn is retried every third off poll across the
			// whole retry budget, then the last state is reported.
			name:            "stuck-off host that refuses PowerOn",
			power:           bmc.PowerStateOff,
			powerOnErr:      errBMC,
			wantState:       bmc.PowerStateOff,
			wantStatusCalls: powerVerifyRetries,
			wantPowerOns:    powerVerifyRetries / 3,
		},
		{
			// Only an "off" report counts toward the stuck-off streak.
			name:            "unknown state never re-issues PowerOn",
			power:           bmc.PowerStateUnknown,
			wantState:       bmc.PowerStateUnknown,
			wantStatusCalls: powerVerifyRetries,
		},
		{
			name:            "every poll fails",
			powerStatusErr:  errBMC,
			wantStatusCalls: powerVerifyRetries,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := bmc.NewMockClient()
			client.Power = tt.power
			client.PowerOnErr = tt.powerOnErr
			client.PowerStatusErr = tt.powerStatusErr
			o := powerTestOrchestrator(nil)

			on, state := o.verifyPowerOn(context.Background(), client, "node-1")

			if on != tt.wantOn {
				t.Errorf("verified on = %v, want %v", on, tt.wantOn)
			}
			if state != tt.wantState {
				t.Errorf("last state = %q, want %q", state, tt.wantState)
			}
			if got := client.PowerStatusCalls(); got != tt.wantStatusCalls {
				t.Errorf("PowerStatus calls = %d, want %d", got, tt.wantStatusCalls)
			}
			if got := client.PowerOnCalls(); got != tt.wantPowerOns {
				t.Errorf("PowerOn calls = %d, want %d", got, tt.wantPowerOns)
			}
		})
	}
}

func TestVerifyPowerOn_CancelledContextStopsPolling(t *testing.T) {
	client := bmc.NewMockClient()
	client.Power = bmc.PowerStateOn
	o := powerTestOrchestrator(nil)
	o.pollTicker = newFakeHealthTicker(0).New
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	on, state := o.verifyPowerOn(ctx, client, "node-1")

	if on {
		t.Error("verified on after cancellation")
	}
	if state != "" {
		t.Errorf("last state = %q, want none", state)
	}
	if got := client.PowerStatusCalls(); got != 0 {
		t.Errorf("PowerStatus calls = %d, want 0", got)
	}
}

func TestDeferredPowerOn(t *testing.T) {
	errBMC := errors.New("bmc unreachable")

	tests := []struct {
		name           string
		power          bmc.PowerState
		powerStatusErr error
		powerOnErr     error
		closeErr       error
		wantPowerOns   int64
		wantPower      bmc.PowerState
	}{
		{
			name:         "off host is powered on",
			power:        bmc.PowerStateOff,
			wantPowerOns: 1,
			wantPower:    bmc.PowerStateOn,
		},
		{
			name:      "on host is left alone",
			power:     bmc.PowerStateOn,
			wantPower: bmc.PowerStateOn,
		},
		{
			name:           "unreadable power state is left alone",
			power:          bmc.PowerStateOff,
			powerStatusErr: errBMC,
			wantPower:      bmc.PowerStateOff,
		},
		{
			// A failed PowerOn and a failed Close are logged; the
			// client is still closed.
			name:         "PowerOn and Close failures",
			power:        bmc.PowerStateOff,
			powerOnErr:   errBMC,
			closeErr:     errBMC,
			wantPowerOns: 1,
			wantPower:    bmc.PowerStateOff,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := bmc.NewMockClient()
			client.Power = tt.power
			client.PowerStatusErr = tt.powerStatusErr
			client.PowerOnErr = tt.powerOnErr
			client.CloseErr = tt.closeErr
			o := powerTestOrchestrator(&mockBMCFactory{client: client})

			o.deferredPowerOn(context.Background(), &bmc.Config{}, "node-1")

			if got := client.PowerOnCalls(); got != tt.wantPowerOns {
				t.Errorf("PowerOn calls = %d, want %d", got, tt.wantPowerOns)
			}
			if client.Power != tt.wantPower {
				t.Errorf("power = %q, want %q", client.Power, tt.wantPower)
			}
			if got := client.CloseCalls(); got != 1 {
				t.Errorf("Close calls = %d, want 1", got)
			}
		})
	}
}

func TestDeferredPowerOn_ClientFactoryFailure(t *testing.T) {
	client := bmc.NewMockClient()
	client.Power = bmc.PowerStateOff
	o := powerTestOrchestrator(&mockBMCFactory{client: client, err: errors.New("no route to BMC")})

	o.deferredPowerOn(context.Background(), &bmc.Config{}, "node-1")

	if got := client.PowerStatusCalls() + client.PowerOnCalls() + client.CloseCalls(); got != 0 {
		t.Errorf("BMC client used %d times after the factory failed, want 0", got)
	}
}
