package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errCompatHandler is the typed failure a compatModeHandler returns from
// Start or Stop when the test arms it.
type errCompatHandler struct {
	op string
}

func (e *errCompatHandler) Error() string { return "compat handler " + e.op + " failed" }

// compatModeHandler is a ServiceHandler whose Start and Stop can be armed to
// fail, so the legacy mode API's failure wrapping can be asserted.
type compatModeHandler struct {
	name     string
	active   bool
	startErr error
	stopErr  error
}

func (h *compatModeHandler) Name() string { return h.name }

func (h *compatModeHandler) Start(ctx context.Context) error {
	if h.startErr != nil {
		return h.startErr
	}
	h.active = true
	return nil
}

func (h *compatModeHandler) Stop(ctx context.Context) error {
	if h.stopErr != nil {
		return h.stopErr
	}
	h.active = false
	return nil
}

func (h *compatModeHandler) IsActive() bool { return h.active }
func (h *compatModeHandler) Health() error  { return nil }

// startCompatGateway runs a gateway with overlay and edge handlers
// registered (both active after Start) and no transit handler.
func startCompatGateway(t *testing.T) (*Gateway, *compatModeHandler, *compatModeHandler) {
	t.Helper()
	gw, err := NewGateway(validConfig())
	require.NoError(t, err)
	overlay := &compatModeHandler{name: ServiceOverlay}
	edge := &compatModeHandler{name: ServiceEdge}
	require.NoError(t, gw.RegisterServiceHandler(overlay))
	require.NoError(t, gw.RegisterServiceHandler(edge))
	gw.SetNodeMetrics(validNodeMetrics())
	require.NoError(t, gw.Start(context.Background()))
	t.Cleanup(func() {
		overlay.stopErr, edge.stopErr = nil, nil
		require.NoError(t, gw.Stop(context.Background()))
	})
	return gw, overlay, edge
}

func TestGatewayMode_StringValidModes(t *testing.T) {
	tests := []struct {
		mode  GatewayMode
		name  string
		valid bool
		modes []GatewayMode
	}{
		{0, "none", false, nil},
		{GatewayModeOverlay, "overlay", true, []GatewayMode{GatewayModeOverlay}},
		{GatewayModeEdge, "edge", true, []GatewayMode{GatewayModeEdge}},
		{GatewayModeTransit, "transit", true, []GatewayMode{GatewayModeTransit}},
		{GatewayModeOverlay | GatewayModeTransit, "mixed", true, []GatewayMode{GatewayModeOverlay, GatewayModeTransit}},
		{GatewayModeOverlay | GatewayModeEdge | GatewayModeTransit, "mixed", true, []GatewayMode{GatewayModeOverlay, GatewayModeEdge, GatewayModeTransit}},
		{GatewayMode(8), "mixed", false, nil},
		{GatewayModeEdge | GatewayMode(16), "mixed", false, []GatewayMode{GatewayModeEdge}},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.name, tc.mode.String(), "String(%d)", tc.mode)
		assert.Equal(t, tc.valid, tc.mode.Valid(), "Valid(%d)", tc.mode)
		assert.Equal(t, tc.modes, tc.mode.Modes(), "Modes(%d)", tc.mode)
	}
	assert.True(t, (GatewayModeOverlay | GatewayModeEdge).HasMode(GatewayModeEdge))
	assert.False(t, GatewayModeOverlay.HasMode(GatewayModeOverlay|GatewayModeEdge))
}

func TestGatewayModeErrors_MessagesAndUnwrap(t *testing.T) {
	cause := &errCompatHandler{op: "start"}

	assert.Equal(t, "gateway mode not supported: transit", (&ErrModeNotSupported{Mode: GatewayModeTransit}).Error())
	assert.Equal(t, "gateway mode not active: edge", (&ErrModeNotActive{Mode: GatewayModeEdge}).Error())
	assert.Equal(t, "gateway mode already active: overlay", (&ErrModeAlreadyActive{Mode: GatewayModeOverlay}).Error())

	activation := &ErrModeActivationFailed{Mode: GatewayModeEdge, Cause: cause}
	assert.Equal(t, "failed to activate gateway mode edge: compat handler start failed", activation.Error())
	assert.Same(t, cause, activation.Unwrap())
	assert.Equal(t, "failed to activate gateway mode edge", (&ErrModeActivationFailed{Mode: GatewayModeEdge}).Error())

	deactivation := &ErrModeDeactivationFailed{Mode: GatewayModeOverlay, Cause: cause}
	assert.Equal(t, "failed to deactivate gateway mode overlay: compat handler start failed", deactivation.Error())
	assert.Same(t, cause, deactivation.Unwrap())
	assert.Equal(t, "failed to deactivate gateway mode overlay", (&ErrModeDeactivationFailed{Mode: GatewayModeOverlay}).Error())
}

func TestGatewayStatus_LegacyModeBitmask(t *testing.T) {
	var nilStatus *GatewayStatus
	assert.Equal(t, uint32(0), nilStatus.LegacyModeBitmask())
	nilStatus.SetLegacyModeBitmask(5) // must not panic on a nil status

	status := &GatewayStatus{}
	status.SetLegacyModeBitmask(uint32(GatewayModeOverlay | GatewayModeTransit))
	assert.Equal(t, GatewayModeOverlay|GatewayModeTransit, status.ActiveModes)
	assert.Equal(t, uint32(5), status.LegacyModeBitmask())
}

func TestGateway_ModeAPIRequiresRunning(t *testing.T) {
	gw, err := NewGateway(validConfig())
	require.NoError(t, err)
	ctx := context.Background()

	assert.ErrorIs(t, gw.ActivateMode(ctx, GatewayModeOverlay), ErrGatewayNotRunning)
	assert.ErrorIs(t, gw.DeactivateMode(ctx, GatewayModeOverlay), ErrGatewayNotRunning)
	assert.Equal(t, GatewayMode(0), gw.GetActiveModes())
	assert.Equal(t, uint32(0), gw.ActiveModeBitmask())
}

func TestGateway_ActiveModesReflectServices(t *testing.T) {
	gw, _, _ := startCompatGateway(t)

	// The firewall service is active too; it maps to no legacy mode.
	assert.Equal(t, GatewayModeOverlay|GatewayModeEdge, gw.GetActiveModes())
	assert.Equal(t, uint32(GatewayModeOverlay|GatewayModeEdge), gw.ActiveModeBitmask())
	assert.True(t, gw.HasMode(GatewayModeOverlay))
	assert.True(t, gw.HasMode(GatewayModeEdge))
	assert.False(t, gw.HasMode(GatewayModeTransit), "no transit handler registered")
	assert.False(t, gw.HasMode(GatewayModeOverlay|GatewayModeEdge), "a combined mode names no service")
}

func TestGateway_ActivateDeactivateModeErrors(t *testing.T) {
	gw, overlay, edge := startCompatGateway(t)
	ctx := context.Background()

	var notSupported *ErrModeNotSupported
	for _, mode := range []GatewayMode{0, GatewayMode(8), GatewayModeOverlay | GatewayModeEdge, GatewayModeTransit} {
		require.ErrorAs(t, gw.ActivateMode(ctx, mode), &notSupported, "activate %d", mode)
		assert.Equal(t, mode, notSupported.Mode)
		require.ErrorAs(t, gw.DeactivateMode(ctx, mode), &notSupported, "deactivate %d", mode)
		assert.Equal(t, mode, notSupported.Mode)
	}

	var already *ErrModeAlreadyActive
	require.ErrorAs(t, gw.ActivateMode(ctx, GatewayModeOverlay), &already)
	assert.Equal(t, GatewayModeOverlay, already.Mode)

	// A failing Stop leaves the mode active and wraps the handler's cause.
	stopCause := &errCompatHandler{op: "stop"}
	edge.stopErr = stopCause
	var deactivation *ErrModeDeactivationFailed
	require.ErrorAs(t, gw.DeactivateMode(ctx, GatewayModeEdge), &deactivation)
	assert.ErrorIs(t, deactivation, stopCause)
	assert.True(t, gw.HasMode(GatewayModeEdge))
	edge.stopErr = nil

	require.NoError(t, gw.DeactivateMode(ctx, GatewayModeOverlay))
	assert.False(t, gw.HasMode(GatewayModeOverlay))
	assert.NotContains(t, gw.activeOrder, ServiceOverlay)
	var notActive *ErrModeNotActive
	require.ErrorAs(t, gw.DeactivateMode(ctx, GatewayModeOverlay), &notActive)
	assert.Equal(t, GatewayModeOverlay, notActive.Mode)

	// A failing Start leaves the mode inactive and wraps the handler's cause.
	startCause := &errCompatHandler{op: "start"}
	overlay.startErr = startCause
	var activation *ErrModeActivationFailed
	require.ErrorAs(t, gw.ActivateMode(ctx, GatewayModeOverlay), &activation)
	assert.ErrorIs(t, activation, startCause)
	assert.False(t, gw.HasMode(GatewayModeOverlay))
	overlay.startErr = nil

	require.NoError(t, gw.ActivateMode(ctx, GatewayModeOverlay))
	assert.True(t, gw.HasMode(GatewayModeOverlay))
	assert.Contains(t, gw.activeOrder, ServiceOverlay)
}

func TestGateway_SetModeBitmask(t *testing.T) {
	gw, _, edge := startCompatGateway(t)
	ctx := context.Background()

	// Dropping a bit deactivates only that mode.
	require.NoError(t, gw.SetModeBitmask(ctx, uint32(GatewayModeEdge)))
	assert.Equal(t, GatewayModeEdge, gw.GetActiveModes())

	// Adding a bit back activates it and leaves the others alone.
	require.NoError(t, gw.SetModeBitmask(ctx, uint32(GatewayModeOverlay|GatewayModeEdge)))
	assert.Equal(t, GatewayModeOverlay|GatewayModeEdge, gw.GetActiveModes())

	// Unchanged bits are a no-op.
	require.NoError(t, gw.SetModeBitmask(ctx, uint32(GatewayModeOverlay|GatewayModeEdge)))
	assert.Equal(t, GatewayModeOverlay|GatewayModeEdge, gw.GetActiveModes())

	// A failing deactivation is reported for the mode it stopped on.
	stopCause := &errCompatHandler{op: "stop"}
	edge.stopErr = stopCause
	var deactivation *ErrModeDeactivationFailed
	require.ErrorAs(t, gw.SetModeBitmask(ctx, uint32(GatewayModeOverlay)), &deactivation)
	assert.Equal(t, GatewayModeEdge, deactivation.Mode)
	assert.ErrorIs(t, deactivation, stopCause)
	edge.stopErr = nil

	// Requesting a mode with no handler deactivates the dropped modes first,
	// then fails activating the missing one.
	var activation *ErrModeActivationFailed
	require.ErrorAs(t, gw.SetModeBitmask(ctx, uint32(GatewayModeTransit)), &activation)
	assert.Equal(t, GatewayModeTransit, activation.Mode)
	var notSupported *ErrModeNotSupported
	assert.True(t, errors.As(activation.Cause, &notSupported))
	assert.Equal(t, GatewayMode(0), gw.GetActiveModes())
}
