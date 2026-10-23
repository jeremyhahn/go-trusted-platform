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

package daemon

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// subsystemService is the registry entry for a platform subsystem named in
// Config.Services. platformd builds these subsystems at start-up and tears
// them down at exit; none of them can be stopped and brought back while the
// process runs. Start and Stop therefore refuse with
// ErrServiceNotControllable, and IsRunning reports the subsystem's real
// state through its probe rather than a flag the verbs could flip.
type subsystemService struct {
	name    string
	reason  string
	running func() bool
}

// Start refuses: the subsystem's lifecycle belongs to the process.
func (s *subsystemService) Start(_ context.Context) error {
	return s.refusal()
}

// Stop refuses: the subsystem's lifecycle belongs to the process.
func (s *subsystemService) Stop(_ context.Context) error {
	return s.refusal()
}

// IsRunning reports whether the subsystem is up in this process.
func (s *subsystemService) IsRunning() bool {
	return s.running()
}

// Name returns the service name.
func (s *subsystemService) Name() string {
	return s.name
}

func (s *subsystemService) refusal() ErrServiceNotControllable {
	return ErrServiceNotControllable{ServiceName: s.name, Reason: s.reason}
}

// processOwned reports the refusal for a ManagedService whose lifecycle
// belongs to the platformd process. The service verbs check it before they
// touch any state, so a refused verb leaves the reported status unchanged.
func processOwned(svc ManagedService) (ErrServiceNotControllable, bool) {
	sub, ok := svc.(*subsystemService)
	if !ok {
		return ErrServiceNotControllable{}, false
	}
	return sub.refusal(), true
}

// subsystemSpec describes one platform subsystem: why the daemon refuses to
// drive it, and how to observe it.
type subsystemSpec struct {
	reason string
	// wired reports whether this daemon built the subsystem. New wires every
	// one of them, so the answer is fixed by the time Start registers the
	// services and holds for the life of the process. nil marks a subsystem
	// the composition root runs outside the daemon; its state comes from the
	// probe set with SetSubsystemProbe.
	wired func(d *Daemon) bool
}

// subsystemSpecs covers every ServiceType a Config.Services entry can name.
var subsystemSpecs = map[platformv1.ServiceType]subsystemSpec{
	platformv1.ServiceType_SERVICE_TYPE_TPM: {
		reason: "the TPM is opened once and shared by the keystores, CA, IDevID and attestation for the life of the process",
		wired:  func(d *Daemon) bool { return d.tpm2Service != nil },
	},
	platformv1.ServiceType_SERVICE_TYPE_SDN: {
		reason: "the SDN service drives the host's Open vSwitch daemon, which platformd does not run",
		wired:  func(d *Daemon) bool { return d.sdnService != nil && d.sdnService.ovsClient != nil },
	},
	platformv1.ServiceType_SERVICE_TYPE_COMPUTE: {
		reason: "the compute orchestrator starts and stops instances, not itself, and closing it is final",
		wired:  func(d *Daemon) bool { return d.computeService != nil && d.computeService.orchestrator != nil },
	},
	platformv1.ServiceType_SERVICE_TYPE_DNS: {
		reason: "platformd serves DNS zone management in-process and runs no DNS server",
		wired:  func(d *Daemon) bool { return d.zoneSvc != nil },
	},
	platformv1.ServiceType_SERVICE_TYPE_ACME: {
		reason: "the ACME server is a set of routes on the web services, with no lifecycle of its own",
	},
	platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE: {
		reason: "the web services carry the REST API and cannot be served again once shut down",
	},
	platformv1.ServiceType_SERVICE_TYPE_ATTESTATION: {
		reason: "attestation reporting is wired once at start-up and stopped once at exit",
		wired:  func(d *Daemon) bool { return d.attestationService != nil && d.attestationService.service != nil },
	},
}
