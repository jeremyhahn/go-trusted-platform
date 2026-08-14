package proxy

import (
	"context"
	"time"
)

// DefaultAttestationMaxAge is the accepted attestation age when a route sets
// RequireAttestation but neither the route nor the config defaults supply an
// AttestationMaxAge. It matches the platform attestation verifier's 24-hour
// manifest freshness policy so the proxy gate and platformd verification
// agree by default.
const DefaultAttestationMaxAge = 24 * time.Hour

// AttestationGate reports whether a device holds a fresh, verified
// attestation. deviceID is the attestation-store host identifier — for
// mutual-TLS clients the chain passes the leaf certificate's Common Name,
// which is the IDevID CN the platform keys attestation manifests on
// (HostManifest.HostID).
//
// A nil return admits the device and marks its identity Attested. Any error
// denies: errors wrapping ErrAttestationStale are a definitive verdict (no
// manifest, manifest older than maxAge, or verification rejected) mapped to
// the "attestation_stale" deny reason; every other error is an indeterminate
// failure mapped to "attestation_unavailable". Both paths fail closed.
type AttestationGate interface {
	Fresh(ctx context.Context, deviceID string, maxAge time.Duration) error
}

// checkAttestation runs the attestation gate for a route that sets
// RequireAttestation and returns a deny decision on any failure. subject is
// the attestation host identifier (empty when the caller has no device
// identity, e.g. a token principal), and the identity's Attested flag is set
// on success.
func (c *Chain) checkAttestation(ctx context.Context, subject, routeID string, req *AuthRequirements, id *ClientIdentity) *AuthDecision {
	if !req.RequireAttestation {
		return nil
	}
	// The engine rejects attestation-requiring routes on a chain without the
	// gate at construction time; deny defensively regardless.
	if c.attestation == nil {
		return deny(ReasonAttestationUnavailable)
	}
	// Token principals carry no device identity, so their attestation state
	// cannot be established. Fail closed rather than admitting unattested
	// callers to an attestation-gated route.
	if subject == "" {
		c.logger.Warn("proxy: attestation required but caller has no device identity",
			"route", routeID)
		return deny(ReasonAttestationUnavailable)
	}
	maxAge := req.AttestationMaxAge
	if maxAge <= 0 {
		maxAge = DefaultAttestationMaxAge
	}
	if err := c.attestation.Fresh(ctx, subject, maxAge); err != nil {
		c.logger.Warn("proxy: attestation gate denied",
			"route", routeID, "device", subject, "max_age", maxAge, "error", err)
		if isStale(err) {
			return deny(ReasonAttestationStale)
		}
		return deny(ReasonAttestationUnavailable)
	}
	id.Attested = true
	return nil
}
