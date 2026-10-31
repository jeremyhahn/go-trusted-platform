package bootstrap

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

func TestPostInstallPowerOn_BringsHostOn(t *testing.T) {
	tests := []struct {
		name       string
		power      bmc.PowerState
		wantOns    int64
		wantResets int64
	}{
		{name: "S5 host is powered on", power: bmc.PowerStateOff, wantOns: 1},
		{name: "running host is reset", power: bmc.PowerStateOn, wantResets: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := bmc.NewMockClient()
			client.Power = tt.power
			o := powerTestOrchestrator(&mockBMCFactory{client: client})

			if err := o.postInstallPowerOn(context.Background(), client, &bmc.Config{}, "node-1"); err != nil {
				t.Fatalf("postInstallPowerOn: %v", err)
			}
			if got := client.PowerOnCalls(); got != tt.wantOns {
				t.Errorf("PowerOn calls = %d, want %d", got, tt.wantOns)
			}
			if got := client.PowerResetCalls(); got != tt.wantResets {
				t.Errorf("PowerReset calls = %d, want %d", got, tt.wantResets)
			}
			// The install-time client and the verify client are both
			// closed.
			if got := client.CloseCalls(); got != 2 {
				t.Errorf("Close calls = %d, want 2", got)
			}
		})
	}
}

func TestPostInstallPowerOn_UnknownStateStillVerifies(t *testing.T) {
	install := bmc.NewMockClient()
	install.Power = bmc.PowerStateUnknown
	verify := bmc.NewMockClient()
	verify.Power = bmc.PowerStateOn
	o := powerTestOrchestrator(&mockBMCFactory{client: verify})

	if err := o.postInstallPowerOn(context.Background(), install, &bmc.Config{}, "node-1"); err != nil {
		t.Fatalf("postInstallPowerOn: %v", err)
	}
	if install.PowerOnCalls() != 0 || install.PowerResetCalls() != 0 {
		t.Error("an unknown state must not be acted on")
	}
}

func TestPostInstallPowerOn_PowerCommandFailures(t *testing.T) {
	errBMC := errors.New("bmc unreachable")
	tests := []struct {
		name   string
		power  bmc.PowerState
		setErr func(*bmc.MockClient)
		wantOp string
	}{
		{"status", bmc.PowerStateOff, func(c *bmc.MockClient) { c.PowerStatusErr = errBMC }, "status"},
		{"power on", bmc.PowerStateOff, func(c *bmc.MockClient) { c.PowerOnErr = errBMC }, "on"},
		{"reset", bmc.PowerStateOn, func(c *bmc.MockClient) { c.PowerResetErr = errBMC }, "reset"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := bmc.NewMockClient()
			client.Power = tt.power
			tt.setErr(client)
			o := powerTestOrchestrator(&mockBMCFactory{client: client})

			err := o.postInstallPowerOn(context.Background(), client, &bmc.Config{}, "node-1")
			var pcErr ErrPowerControlFailed
			if !errors.As(err, &pcErr) {
				t.Fatalf("err = %v, want ErrPowerControlFailed", err)
			}
			if pcErr.Operation != tt.wantOp || pcErr.Hostname != "node-1" || !errors.Is(pcErr.Cause, errBMC) {
				t.Errorf("err = %+v, want operation %q for node-1 caused by the BMC error", pcErr, tt.wantOp)
			}
		})
	}
}

func TestPostInstallPowerOn_ReconnectFailure(t *testing.T) {
	client := bmc.NewMockClient()
	client.Power = bmc.PowerStateOff
	errDial := errors.New("dial refused")
	o := powerTestOrchestrator(&mockBMCFactory{err: errDial})

	err := o.postInstallPowerOn(context.Background(), client, &bmc.Config{}, "node-1")
	var reErr ErrBMCReconnect
	if !errors.As(err, &reErr) {
		t.Fatalf("err = %v, want ErrBMCReconnect", err)
	}
	if reErr.Operation != "post-install power verify" || !errors.Is(reErr.Cause, errDial) {
		t.Errorf("err = %+v, want the post-install verify reconnect caused by the dial error", reErr)
	}
}

// TestPostInstallPowerOn_VerificationFailureReportsObservedState is the
// regression for the failure that always claimed the host was off: the
// reported state is the last one the BMC returned.
func TestPostInstallPowerOn_VerificationFailureReportsObservedState(t *testing.T) {
	tests := []struct {
		name       string
		power      bmc.PowerState
		statusErr  error
		wantActual string
		wantOns    int64
	}{
		{
			// Each off report re-issues PowerOn; the BMC refuses it.
			name:       "stuck off",
			power:      bmc.PowerStateOff,
			wantActual: string(bmc.PowerStateOff),
			wantOns:    int64(powerVerifyRetries),
		},
		{
			name:       "unknown",
			power:      bmc.PowerStateUnknown,
			wantActual: string(bmc.PowerStateUnknown),
		},
		{
			// No poll answered, so no state was observed.
			name:       "status never readable",
			power:      bmc.PowerStateOff,
			statusErr:  errors.New("bmc busy"),
			wantActual: string(bmc.PowerStateUnknown),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			install := bmc.NewMockClient()
			install.Power = bmc.PowerStateOn
			verify := bmc.NewMockClient()
			verify.Power = tt.power
			verify.PowerOnErr = errors.New("power on refused")
			verify.PowerStatusErr = tt.statusErr
			o := powerTestOrchestrator(&mockBMCFactory{client: verify})

			err := o.postInstallPowerOn(context.Background(), install, &bmc.Config{}, "node-1")
			var vErr ErrPowerStateVerificationFailed
			if !errors.As(err, &vErr) {
				t.Fatalf("err = %v, want ErrPowerStateVerificationFailed", err)
			}
			if vErr.Actual != tt.wantActual || vErr.Expected != string(bmc.PowerStateOn) || vErr.Retries != powerVerifyRetries {
				t.Errorf("err = %+v, want actual %q after %d retries", vErr, tt.wantActual, powerVerifyRetries)
			}
			if got := verify.PowerOnCalls(); got != tt.wantOns {
				t.Errorf("PowerOn retries = %d, want %d", got, tt.wantOns)
			}
		})
	}
}

func TestPostInstallPowerOn_CancelledContextStopsVerify(t *testing.T) {
	client := bmc.NewMockClient()
	client.Power = bmc.PowerStateOn
	o := powerTestOrchestrator(&mockBMCFactory{client: client})
	// No queued ticks: the only ready case is the cancelled context.
	o.pollTicker = newFakeHealthTicker(0).New
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := o.postInstallPowerOn(ctx, client, &bmc.Config{}, "node-1")
	var pcErr ErrPowerControlFailed
	if !errors.As(err, &pcErr) || pcErr.Operation != "post-install-verify" || !errors.Is(pcErr.Cause, context.Canceled) {
		t.Fatalf("err = %v, want post-install-verify ErrPowerControlFailed caused by cancellation", err)
	}
}
