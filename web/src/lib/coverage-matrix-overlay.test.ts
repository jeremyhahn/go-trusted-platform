// @vitest-environment node
import fs from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

const matrix = fs
  .readFileSync(path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md'), 'utf8')
  .split('\n')

const page = '`(dashboard)/networking/overlays/vteps/page.tsx`'
const spec = '`real-server/overlay-vteps.spec.ts`'

const rows: Array<[string, string]> = [
  ['ListVTEPs', 'GET /vteps'],
  ['GetVTEP', 'GET /vteps/{nodeId}'],
  ['DeleteVNI', 'DELETE /vnis/{vni:[0-9]+}'],
  ['ListTunnels', 'GET /tunnels'],
  ['GetTunnelStats', 'GET /tunnels/stats'],
  ['ListRemoteMACs', 'GET /macs'],
  ['ForgetMAC', 'DELETE /macs'],
  ['GetOverlayStatus', 'GET /status'],
]

describe('coverage matrix: OverlayService', () => {
  it('lists the vteps page operations as covered by the real-server spec', () => {
    for (const [op, route] of rows) {
      const want = `| \`OverlayService.${op}\` | \`${route}\` | ${page} | - | ${spec} | covered |`
      expect(matrix.filter((line) => line === want), op).toHaveLength(1)
    }
    const open = matrix.filter(
      (line) =>
        line.startsWith('| `OverlayService.') &&
        (line.endsWith('| partial |') || line.endsWith('| missing |')),
    )
    expect(open).toEqual([])
  })

  it('names files that exist', () => {
    expect(
      fs.existsSync(path.resolve(process.cwd(), 'src/app/(dashboard)/networking/overlays/vteps/page.tsx')),
    ).toBe(true)
    expect(fs.existsSync(path.resolve(process.cwd(), 'e2e/real-server/overlay-vteps.spec.ts'))).toBe(true)
  })
})
