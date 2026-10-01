# iPXE builder

Builds the arm64 EFI iPXE the PXE server serves to an AArch64 client —
a Raspberry Pi after its U-Boot stage, or the QEMU virt stand-in — from
one pinned upstream release, inside an Alpine container:

| Target | Served as | Used for |
|---|---|---|
| `bin-arm64-efi/snponly.efi` | `snponly-aarch64.efi` (DHCP client architecture `0x000b` / `0x0016`) | every network-booting AArch64 node |

```
make build          # output/bin-arm64-efi/snponly.efi + SHA256SUMS, manifest.json
make verify         # recompute SHA256SUMS
```

or, from the repository root, `make ipxe-build`. The build is skipped when
`output/manifest.json` already carries the cache key of the current inputs
(the iPXE version, the targets, `configs/*.h`, this Dockerfile and the
build script).

## Why not upstream's binary

`boot.ipxe.org` serves the same `arm64-efi/snponly.efi`, and the PXE
server would fetch it — but it cannot run under U-Boot. iPXE's EFI nap
executes WFI whenever it waits (its banner prompt, DHCP, every download)
and relies on the firmware's timer interrupt to wake the CPU. U-Boot's EFI
implementation is polled: timer events fire inside boot-service calls and
never from an interrupt, so the WFI is never woken. The symptom is iPXE
printing `Press Ctrl-B for the iPXE command line...` and stopping, with the
vCPU idle at a `wfi` (measured over QMP on QEMU virt with U-Boot 2026.07
and iPXE 2.0.0, 2026-09-22; upstream tracks it as ipxe/ipxe discussion
#605). `configs/nap.h` selects `NAP_NULL`, which spins instead; every wait
then keeps calling boot services, which is what dispatches U-Boot's timers.
Nothing else differs from upstream's snponly build.

The PXE server serves this build through `ServerConfig.FirmwareOverrides`
(the `platformctl iso test pxe --ipxe` flag; the bootstrap container's
wiring comes with the Raspberry Pi netboot stage). It is
Authenticode-signed with the platform's db key on the way out, like every
EFI binary the server hands to a Secure Boot client.

## x86

The x86 binaries (`ipxe.efi`, `ipxe32.efi`, `undionly.kpxe`) stay
upstream's: OVMF and vendor UEFI deliver timer interrupts, and those
builds have been in production on the platform's boot servers. Add a
target here only when an x86 build needs a platform-specific option.
