// @vitest-environment node
import fs from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

// #2044: every op a compute page or card passes to <Gated> must be a route
// the server serves. A typo would read "not offered by this server" on the
// control while every component test (which stubs the capability list with
// the same string) stays green.

const goldenPath = path.resolve(process.cwd(), '..', 'pkg', 'webservice', 'v1', 'testdata', 'routes.golden')
const served = new Set(
  fs
    .readFileSync(goldenPath, 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== ''),
)

const files = [
  'src/app/(dashboard)/compute/vms/page.tsx',
  'src/app/(dashboard)/compute/vms/[id]/vm-detail-client.tsx',
  'src/app/(dashboard)/compute/snapshots/page.tsx',
  'src/app/(dashboard)/compute/snapshots/[snapshotId]/snapshot-detail-client.tsx',
  'src/app/(dashboard)/compute/migrations/page.tsx',
  'src/components/features/compute/vm-table.tsx',
  'src/components/features/compute/vm-disks-card.tsx',
  'src/components/features/compute/vm-attest-card.tsx',
  'src/components/features/compute/vm-metrics.tsx',
  'src/components/features/compute/vm-migrate-dialog.tsx',
]

const OP = String.raw`(?:GET|POST|PUT|PATCH|DELETE) /api/v1/[^'"\x60\s]*`
const patterns = [
  // <Gated op="METHOD /api/v1/...">
  new RegExp(String.raw`\bop="(${OP})"`, 'g'),
  // const START_OP = 'METHOD /api/v1/...'
  new RegExp(String.raw`_OP\s*=\s*['"](${OP})['"]`, 'g'),
]

function gatedOps(file: string): string[] {
  const source = fs.readFileSync(path.resolve(process.cwd(), file), 'utf8')
  const ops: string[] = []
  for (const re of patterns) {
    for (const m of source.matchAll(re)) ops.push(m[1])
  }
  return ops
}

describe('compute gated ops are served routes', () => {
  it('reads the route golden', () => {
    expect(served.size).toBeGreaterThan(0)
    expect(served.has('GET /api/v1/compute/vms')).toBe(true)
  })

  it.each(files)('%s gates only served routes', (file) => {
    const ops = gatedOps(file)
    expect(ops.length, `${file} gates at least one op`).toBeGreaterThan(0)
    for (const op of ops) {
      expect(served.has(op), `${file}: ${op} is in routes.golden`).toBe(true)
    }
  })
})
