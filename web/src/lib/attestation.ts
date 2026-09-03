/**
 * ATTESTATION_UNAVAILABLE is the single reason string shown wherever the
 * console offers per-device attestation.
 *
 * The control plane has a real device-quote verifier
 * (PlatformServiceProvider.DeviceAttest) but no collector: nothing asks a
 * node for a fresh quote. The controls previously called
 * collectHostAttestation(), which attests the CONTROL PLANE's own TPM,
 * discarded the device id, and then reported success for the selected
 * device — a green result for a machine that was never attested.
 *
 * Disabled is the honest state until the attestation reporting service
 * lands (#226).
 */
export const ATTESTATION_UNAVAILABLE =
  'Per-device attestation is unavailable: the control plane cannot attest this device on demand yet (#226).';
