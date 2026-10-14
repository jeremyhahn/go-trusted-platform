package health

import (
	"context"
	"time"
)

// Probe is the verdict of a liveness, readiness or aggregate health probe.
// It carries the status only, never a component name or detail, so every
// transport can serve it to an unauthenticated caller.
type Probe struct {
	// OK is the probe's answer: alive, ready, or healthy.
	OK bool

	// Status is the overall registry verdict the answer was derived from.
	Status HealthStatus

	// Timestamp is when the probe was taken.
	Timestamp time.Time
}

// Liveness reports that the process is answering. It consults nothing: a
// caller that receives the answer has proved liveness by receiving it.
func Liveness() Probe {
	return Probe{OK: true, Status: StatusHealthy, Timestamp: time.Now()}
}

// Readiness reports whether the platform can take traffic: it is ready when
// no registered checker is unhealthy. A degraded component or one whose check
// timed out does not make the platform unready; a closed registry does.
func Readiness(ctx context.Context, registry Registry) Probe {
	probe := sweep(ctx, registry)
	probe.OK = probe.Status != StatusUnhealthy
	return probe
}

// Aggregate reports whether every registered checker is healthy. Any
// degraded, unhealthy or unanswered component makes it not OK.
func Aggregate(ctx context.Context, registry Registry) Probe {
	probe := sweep(ctx, registry)
	probe.OK = probe.Status == StatusHealthy
	return probe
}

// sweep runs one registry check and keeps only its verdict. A nil registry
// answers healthy: the documented fail-open for an unwired registry.
func sweep(ctx context.Context, registry Registry) Probe {
	if registry == nil {
		return Probe{Status: StatusHealthy, Timestamp: time.Now()}
	}
	system := registry.Check(ctx)
	return Probe{Status: system.Status, Timestamp: system.Timestamp}
}
