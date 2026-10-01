/*
 * iPXE config/local/nap.h for the platform's arm64 EFI build.
 *
 * NAP_EFI halts the CPU (WFI on ARM) whenever iPXE waits — at its banner
 * prompt, in DHCP, in every download — and relies on the firmware's timer
 * interrupt to wake it. U-Boot's EFI implementation is polled: its timer
 * events fire inside boot-service calls, never from an interrupt, so the
 * WFI is never woken and iPXE hangs at "Press Ctrl-B for the iPXE command
 * line" with the vCPU idle (measured on QEMU virt, U-Boot 2026.07, iPXE
 * 2.0.0, 2026-09-22). NAP_NULL spins instead; every wait then keeps
 * calling boot services, which is what dispatches U-Boot's timers.
 */
#undef NAP_EFI
#define NAP_NULL
