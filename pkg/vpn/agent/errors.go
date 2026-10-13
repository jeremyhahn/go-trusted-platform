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

package agent

import (
	"fmt"
	"net/http"
	"strings"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// RefusedError is a refusal from the gateway: the class it named, the
// posture rules that failed (posture violations only) and the HTTP status.
type RefusedError struct {
	Status int
	Class  gwvpn.RefusalClass
	Rules  []string
}

// refusalPhrases overrides the printed phrase where the class name would read
// badly; every other class prints with its dashes as spaces.
var refusalPhrases = map[gwvpn.RefusalClass]string{
	gwvpn.RefusalPostureUnavailable: "posture policy",
}

func (e *RefusedError) Error() string {
	phrase, ok := refusalPhrases[e.Class]
	if !ok {
		phrase = strings.ReplaceAll(strings.TrimSuffix(string(e.Class), "-unavailable"), "-", " ")
	}
	verb := "refused"
	if e.Status == http.StatusServiceUnavailable {
		verb = "unavailable"
	}
	if len(e.Rules) > 0 {
		return verb + ": " + phrase + ": " + strings.Join(e.Rules, ", ")
	}
	return verb + ": " + phrase
}

// ErrNotConnected is returned when the agent holds no lease.
type ErrNotConnected struct{}

func (e *ErrNotConnected) Error() string { return "not connected" }

// ErrAlreadyConnected is returned by Connect while a lease is held.
type ErrAlreadyConnected struct {
	Gateway string
	LeaseID gwvpn.LeaseID
}

func (e *ErrAlreadyConnected) Error() string {
	return fmt.Sprintf("already connected to %s (lease %s); disconnect first", e.Gateway, e.LeaseID)
}

// ErrInvalidOptions is returned for an agent built or called with a missing
// or invalid setting.
type ErrInvalidOptions struct {
	Field  string
	Reason string
}

func (e *ErrInvalidOptions) Error() string {
	return fmt.Sprintf("vpn agent: invalid %s: %s", e.Field, e.Reason)
}

// ErrGatewayUnreachable is returned when the request never got an answer.
type ErrGatewayUnreachable struct {
	Gateway string
	Cause   error
}

func (e *ErrGatewayUnreachable) Error() string {
	return fmt.Sprintf("gateway %s unreachable: %v", e.Gateway, e.Cause)
}

func (e *ErrGatewayUnreachable) Unwrap() error { return e.Cause }

// ErrInvalidResponse is returned when the gateway answered with something
// that is not the admission contract.
type ErrInvalidResponse struct {
	Gateway string
	Reason  string
}

func (e *ErrInvalidResponse) Error() string {
	return fmt.Sprintf("gateway %s: invalid response: %s", e.Gateway, e.Reason)
}

// ErrEvidence is returned when the agent could not produce one piece of its
// evidence: the device certificate, the quote, the posture report or the
// person factor.
type ErrEvidence struct {
	Step  string
	Cause error
}

func (e *ErrEvidence) Error() string {
	return fmt.Sprintf("collect %s: %v", e.Step, e.Cause)
}

func (e *ErrEvidence) Unwrap() error { return e.Cause }

// ErrPostureFact is returned when one posture fact could not be read. A
// fact the host does not have (no efivarfs, no securityfs) is reported as
// unavailable rather than as this error.
type ErrPostureFact struct {
	Fact  string
	Cause error
}

func (e *ErrPostureFact) Error() string {
	return fmt.Sprintf("posture fact %s: %v", e.Fact, e.Cause)
}

func (e *ErrPostureFact) Unwrap() error { return e.Cause }

// ErrNoRootMount is returned when the mount table has no root mount.
type ErrNoRootMount struct {
	MountInfo string
}

func (e *ErrNoRootMount) Error() string {
	return "no root mount in " + e.MountInfo
}

// ErrDataPlaneUnsupported is returned when this build has no client for the
// data plane: WireGuard in a FIPS build.
type ErrDataPlaneUnsupported struct {
	Kind gwvpn.DataPlaneKind
}

func (e *ErrDataPlaneUnsupported) Error() string {
	return fmt.Sprintf("data plane %s not available", e.Kind)
}

// ErrDataPlane is returned when the client data plane failed to come up or
// go down.
type ErrDataPlane struct {
	Op    string
	Kind  gwvpn.DataPlaneKind
	Cause error
}

func (e *ErrDataPlane) Error() string {
	return fmt.Sprintf("data plane %s %s: %v", e.Kind, e.Op, e.Cause)
}

func (e *ErrDataPlane) Unwrap() error { return e.Cause }

// ErrStateStore is returned when the lease state file could not be read,
// written or removed.
type ErrStateStore struct {
	Op    string
	Path  string
	Cause error
}

func (e *ErrStateStore) Error() string {
	return fmt.Sprintf("vpn state %s %s: %v", e.Op, e.Path, e.Cause)
}

func (e *ErrStateStore) Unwrap() error { return e.Cause }

// ErrRollback is returned when Connect failed after admission and undoing
// the admission failed too. It unwraps to the failure only, so the exit code
// reflects what went wrong rather than the cleanup.
type ErrRollback struct {
	Cause    error
	Rollback error
}

func (e *ErrRollback) Error() string {
	return fmt.Sprintf("%v (rollback: %v)", e.Cause, e.Rollback)
}

func (e *ErrRollback) Unwrap() error { return e.Cause }
