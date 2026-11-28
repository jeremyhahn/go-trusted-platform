import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// Codex round 5 on #2180: a page importing Gated twice does not compile, so
// each page that uses the capability gate imports it exactly once.

describe('Gated imports', () => {
  it.each([
    'src/app/(dashboard)/tpm/pcrs/page.tsx',
    'src/app/(dashboard)/networking/dns/page.tsx',
    'src/app/(dashboard)/networking/sdn/page.tsx',
  ])('%s imports Gated once', (path) => {
    const source = readFileSync(join(process.cwd(), path), 'utf8');
    expect(source.match(/^import \{ Gated \} from /gm)?.length ?? 0).toBe(1);
  });
});
