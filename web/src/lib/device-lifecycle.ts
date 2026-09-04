/**
 * DEVICE_TOGGLE_UNAVAILABLE is the single reason string shown wherever
 * the console offers Enable / Disable Device.
 *
 * There is no server-side operator enable/disable. `PUT /v1/devices/{id}`
 * is served, but its wire contract carries no state field — neither
 * DeviceRequest nor the proto Device message has one — and
 * `device.Service.Update` deliberately restores every server-owned field
 * from the stored record, because "a caller that really owns one of these
 * transitions goes through its dedicated flow (activation, quarantine,
 * heartbeat), never a generic update".
 *
 * The controls previously called a mutation whose whole body was
 * `return { data: {}, error: undefined, success: true }`, then toasted
 * "Device disabled successfully" — an operator was told a live machine
 * had been cut off when nothing had been sent anywhere.
 *
 * Disabled is the honest state until the device lifecycle transition flow
 * lands (#250).
 */
export const DEVICE_TOGGLE_UNAVAILABLE =
  'Enable/Disable is unavailable: the control plane has no operator device lifecycle transition yet (#250).';
