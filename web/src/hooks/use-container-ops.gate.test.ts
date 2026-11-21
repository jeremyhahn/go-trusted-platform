import { describe, expect, it } from 'vitest';
import type { Container } from 'trusted-platform-sdk';
import { containerControlGates, vmVerifyGate } from './use-container-ops';

const container = (state: string): Container =>
  ({ id: 'c1', state, config: { name: 'web', image: 'busybox' } }) as unknown as Container;

describe('containerControlGates (#2045)', () => {
  it('disables exec and attest with a reason while no container is loaded', () => {
    const gates = containerControlGates(null, false);
    expect(gates.exec.enabled).toBe(false);
    expect(gates.attest.enabled).toBe(false);
    expect(gates.exec.reason).toMatch(/not loaded/i);
    expect(gates.attest.reason).toMatch(/not loaded/i);
  });

  it('enables exec and attest on a running container', () => {
    const gates = containerControlGates(container('CONTAINER_STATE_RUNNING'), false);
    expect(gates.exec).toEqual({ enabled: true, reason: null });
    expect(gates.attest).toEqual({ enabled: true, reason: null });
  });

  it('disables exec on a stopped container and names its state', () => {
    const gates = containerControlGates(container('CONTAINER_STATE_STOPPED'), false);
    expect(gates.exec.enabled).toBe(false);
    expect(gates.exec.reason).toMatch(/running/i);
    expect(gates.exec.reason).toContain('stopped');
    expect(gates.attest.enabled).toBe(true);
  });

  it('disables both while an action is in flight', () => {
    const gates = containerControlGates(container('CONTAINER_STATE_RUNNING'), true);
    expect(gates.exec.enabled).toBe(false);
    expect(gates.attest.enabled).toBe(false);
    expect(gates.exec.reason).toMatch(/in progress/i);
  });
});

describe('vmVerifyGate (#2045)', () => {
  it('enables verify on a running VM', () => {
    expect(vmVerifyGate('running', false)).toEqual({ enabled: true, reason: null });
  });

  it('disables verify on a VM that is not running and names its state', () => {
    const gate = vmVerifyGate('stopped', false);
    expect(gate.enabled).toBe(false);
    expect(gate.reason).toContain('stopped');
  });

  it('disables verify while a verification is in flight', () => {
    const gate = vmVerifyGate('running', true);
    expect(gate.enabled).toBe(false);
    expect(gate.reason).toMatch(/in progress/i);
  });
});
