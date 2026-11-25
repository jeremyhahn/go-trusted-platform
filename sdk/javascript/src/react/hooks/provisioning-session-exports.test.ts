import { describe, expectTypeOf, it } from 'vitest';

import type {
  UseProvisioningSessionResult as RootResult,
  UseProvisioningSessionsOptions as RootOptions,
} from '../../index.js';
import type {
  UseProvisioningSessionResult as ReactResult,
  UseProvisioningSessionsOptions as ReactOptions,
} from '../index.js';

// package.json exposes only the root and ./react entry points, so the options
// type of useProvisioningSessions must be forwarded by both public barrels.
describe('provisioning session hook type exports', () => {
  it('the root and react barrels export UseProvisioningSessionsOptions', () => {
    expectTypeOf<RootOptions>().toEqualTypeOf<{ enabled?: boolean }>();
    expectTypeOf<ReactOptions>().toEqualTypeOf<{ enabled?: boolean }>();
    expectTypeOf<RootResult>().toEqualTypeOf<ReactResult>();
  });
});
