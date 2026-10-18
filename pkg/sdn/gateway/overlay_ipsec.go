package gateway

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	ipsecconfig "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/config"
)

// OverlayIPsec carries the overlay's VTEP-to-VTEP traffic in transport-mode
// ESP behind a fail-closed floor. It is the ipsec.Service the assembly
// builds with ipsec.NewEVPNService.
type OverlayIPsec interface {
	// Install puts the fail-closed floor in.
	Install(ctx context.Context) error
	// Run keeps the IPsec daemon attached until ctx ends.
	Run(ctx context.Context)
	// Close releases the service; the floor stays installed.
	Close()
	// HandleEVPNRoute follows a Type-3 route: a VTEP is a peer while an
	// admitted route names it.
	HandleEVPNRoute(ctx context.Context, route *bgp.EVPNRouteData) error
	// Evict ends a peer's SAs and drops its packets until Readmit.
	Evict(ctx context.Context, peer netip.Addr) error
	// Readmit lifts an eviction; a peer not evicted is left as it is.
	Readmit(ctx context.Context, peer netip.Addr) error
}

// OverlayIPsecFactory builds the overlay's IPsec for an enabled ipsec
// section. Its controller asks admitter before it brings up an SA to a VTEP
// a route names.
type OverlayIPsecFactory func(cfg *ipsecconfig.Config, admitter modes.VTEPAdmitter, logger *slog.Logger) (OverlayIPsec, error)

// overlayIPsecPeers follows the overlay's flood lists in IPsec. A VTEP put
// on a flood list was admitted just now, so an eviction left from an
// earlier revocation is lifted before its SA is asked for.
func overlayIPsecPeers(ipsec OverlayIPsec) bgp.EVPNRouteHandler {
	return func(ctx context.Context, route *bgp.EVPNRouteData) error {
		if !route.IsWithdraw && route.IMET != nil {
			if err := ipsec.Readmit(ctx, route.IMET.VTEPIP); err != nil {
				return err
			}
		}
		return ipsec.HandleEVPNRoute(ctx, route)
	}
}

// admittedVTEPs admits, for IPsec, a VTEP the overlay's admitter holds a
// fresh admission for. It reads no platform state.
type admittedVTEPs struct {
	admitter *VTEPAdmitter
}

// AdmitVTEP implements modes.VTEPAdmitter.
func (v admittedVTEPs) AdmitVTEP(_ context.Context, _ uint32, vtep netip.Addr) error {
	if v.admitter.verdictStillFresh(vtep) {
		return nil
	}
	return ErrOverlayVTEPNotAdmitted{VTEP: vtep}
}

// ErrOverlayVTEPNotAdmitted reports a VTEP IPsec was asked to bring up an SA
// to without a fresh admission from the overlay's admitter.
type ErrOverlayVTEPNotAdmitted struct {
	VTEP netip.Addr
}

func (e ErrOverlayVTEPNotAdmitted) Error() string {
	return "gateway overlay ipsec: VTEP " + e.VTEP.String() + " holds no fresh admission"
}

// ErrOverlayIPsec reports an overlay IPsec service that could not be
// built or could not install its floor.
type ErrOverlayIPsec struct {
	Operation string
	Cause     error
}

func (e *ErrOverlayIPsec) Error() string {
	return "gateway overlay ipsec: " + e.Operation + ": " + e.Cause.Error()
}

func (e *ErrOverlayIPsec) Unwrap() error { return e.Cause }
