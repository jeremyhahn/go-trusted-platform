// @vitest-environment node
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const lines = fs
  .readFileSync(path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md'), 'utf8')
  .split('\n');

const H = '`(dashboard)/platform/health/page.tsx`';
const S = '`(dashboard)/platform/services/page.tsx`';
const C = '`(dashboard)/platform/config/page.tsx`';
const D = '`real-server/platform-daemon.spec.ts`';
const P = '`real-server/platform-config.spec.ts`';
const ctl = '`Dashboard.svelte`';

// [op, route, page, platformctl, spec]
const rows: Array<[string, string, string, string, string]> = [
  ['GetStatus', 'GET /status', H, ctl, D],
  ['Liveness', 'GET /liveness', H, '-', D],
  ['Readiness', 'GET /readiness', H, '-', D],
  ['Shutdown', 'POST /shutdown', H, '-', D],
  ['GetVersion', 'GET /version', H, ctl, D],
  ['GetConfig', 'GET /config', C, '-', P],
  ['UpdateConfig', 'PUT /config/sections/{section}', C, '-', P],
  ['ReloadConfig', 'POST /config/reload', C, '-', P],
  ['StartService', 'POST /services/{service}/start', S, ctl, D],
  ['StopService', 'POST /services/{service}/stop', S, ctl, D],
  ['RestartService', 'POST /services/{service}/restart', S, ctl, D],
  ['GetServiceStatus', 'GET /services/{service}', S, '-', D],
  ['ListServices', 'GET /services', S, ctl, D],
  ['ListEntityTypes', 'GET /entity-types', H, '-', D],
];

describe('coverage matrix: PlatformDaemon', () => {
  it('lists each slice-10 operation as covered', () => {
    for (const [op, route, page, platformctl, spec] of rows) {
      const want = `| \`PlatformDaemon.${op}\` | \`${route}\` | ${page} | ${platformctl} | ${spec} | covered |`;
      expect(lines.filter((l) => l === want), op).toHaveLength(1);
    }
    const open = lines.filter(
      (l) =>
        l.startsWith('| `PlatformDaemon.') && (l.endsWith('| partial |') || l.endsWith('| missing |')),
    );
    expect(open).toEqual([]);
  });

  it('names files that exist', () => {
    for (const f of [
      'src/app/(dashboard)/platform/health/page.tsx',
      'src/app/(dashboard)/platform/services/page.tsx',
      'src/app/(dashboard)/platform/config/page.tsx',
      'e2e/real-server/platform-daemon.spec.ts',
      'e2e/real-server/platform-config.spec.ts',
    ]) {
      expect(fs.existsSync(path.resolve(process.cwd(), f)), f).toBe(true);
    }
  });
});
