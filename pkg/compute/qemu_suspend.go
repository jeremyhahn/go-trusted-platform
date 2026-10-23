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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

// vmRunControl abstracts the QMP run-state commands the orchestrator uses to
// suspend and resume a VM (stop / cont) so tests can inject a fake QMP seam.
type vmRunControl interface {
	Pause(ctx context.Context) error
	Resume(ctx context.Context) error
}

// Compile-time proof that the real monitor satisfies the run-control seam.
var _ vmRunControl = (*qemu.Monitor)(nil)

// Compile-time proof that the QEMU orchestrator offers suspend and resume.
var _ VMSuspender = (*QEMUOrchestrator)(nil)

// Seams for run control. They are package-level function variables so unit
// tests can substitute the QMP monitor and the QEMU process without a real VM.
var (
	// vmRunControlFor returns the QMP run-state operations for an instance.
	vmRunControlFor = defaultVMRunControlFor

	// stopVMProcess powers the instance's QEMU process off.
	stopVMProcess = defaultStopVMProcess
)

// instanceMonitor returns the instance's QMP monitor, connecting it first when
// it is not connected yet.
func instanceMonitor(ctx context.Context, inst *qemuInstance) (*qemu.Monitor, error) {
	mon := inst.vm.Monitor()
	if mon == nil || !mon.IsConnected() {
		if err := inst.vm.ConnectMonitor(ctx); err != nil {
			return nil, &WrappedError{Msg: "failed to connect QMP monitor", Err: err}
		}
		mon = inst.vm.Monitor()
	}
	return mon, nil
}

// defaultVMRunControlFor returns the real QMP monitor for the instance.
func defaultVMRunControlFor(ctx context.Context, inst *qemuInstance) (vmRunControl, error) {
	mon, err := instanceMonitor(ctx, inst)
	if err != nil {
		return nil, err
	}
	return mon, nil
}

// defaultStopVMProcess stops the QEMU process: SIGKILL for a forced stop,
// otherwise ACPI powerdown over QMP, then SIGTERM when the guest does not
// answer within the timeout (the QEMU default when opts has none).
func defaultStopVMProcess(inst *qemuInstance, opts StopOptions) error {
	switch {
	case opts.Force:
		return inst.vm.ForceStop()
	case opts.Timeout > 0:
		return inst.vm.StopWithTimeout(opts.Timeout)
	default:
		return inst.vm.Stop()
	}
}

// Suspend pauses a running VM's vCPUs with the QMP stop command. The guest
// keeps its memory and devices and continues where it stopped on Resume.
func (o *QEMUOrchestrator) Suspend(ctx context.Context, instanceID string) error {
	return o.changeRunState(ctx, instanceID, StateRunning, StateSuspended, ErrInstanceNotRunning,
		"suspend", vmRunControl.Pause)
}

// Resume continues a suspended VM with the QMP cont command.
func (o *QEMUOrchestrator) Resume(ctx context.Context, instanceID string) error {
	return o.changeRunState(ctx, instanceID, StateSuspended, StateRunning, ErrInstanceNotSuspended,
		"resume", vmRunControl.Resume)
}

// changeRunState moves an instance from one run state to another through a
// QMP run-state command. The instance must be in the from state; otherwise
// wrongState is returned and nothing is sent to QEMU.
func (o *QEMUOrchestrator) changeRunState(
	ctx context.Context,
	instanceID string,
	from, to InstanceState,
	wrongState error,
	verb string,
	command func(vmRunControl, context.Context) error,
) error {
	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	o.mu.RLock()
	inst, exists := o.instances[instanceID]
	o.mu.RUnlock()
	if !exists {
		return ErrInstanceNotFound
	}

	inst.mu.Lock()
	defer inst.mu.Unlock()

	state, err := o.lifecycle.GetState(instanceID)
	if err != nil {
		return err
	}
	if state != from {
		return &SentinelCauseError{
			Sentinel: wrongState,
			Cause:    &MessageError{Msg: "cannot " + verb + " instance in state " + string(state)},
		}
	}

	runControl, err := vmRunControlFor(ctx, inst)
	if err != nil {
		return err
	}
	if err := command(runControl, ctx); err != nil {
		return &WrappedError{Msg: "failed to " + verb + " VM", Err: err}
	}

	if err := o.lifecycle.SetState(instanceID, to); err != nil {
		return err
	}
	inst.instance.State = to
	inst.instance.UpdatedAt = time.Now()

	o.logger.Infof("VM %s: %s", instanceID, to)
	return nil
}

// continueBeforeStop sends QMP cont to a suspended instance so the guest can
// process the ACPI powerdown that Stop sends next. A failure is logged, not
// returned: Stop falls back to SIGTERM when the guest does not answer.
// The caller holds inst.mu.
func (o *QEMUOrchestrator) continueBeforeStop(ctx context.Context, inst *qemuInstance) {
	runControl, err := vmRunControlFor(ctx, inst)
	if err == nil {
		err = runControl.Resume(ctx)
	}
	if err != nil {
		o.logger.Warnf("Failed to continue suspended VM %s before stop: %v", inst.instance.ID, err)
	}
}
