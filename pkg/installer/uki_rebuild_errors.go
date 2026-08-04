// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package installer

import "fmt"

// ErrKernelImageNotFound is returned when no kernel image can be located for the
// requested kernel version under the boot directory.
type ErrKernelImageNotFound struct {
	Kver    string
	BootDir string
}

func (e *ErrKernelImageNotFound) Error() string {
	return fmt.Sprintf("uki-rebuild: kernel image for %q not found under %s (looked for vmlinuz-%s / vmlinuz-lts / vmlinuz-fips)",
		e.Kver, e.BootDir, e.Kver)
}

// ErrKernelCmdlineUnavailable is returned when the persisted kernel command line
// cannot be read. The rebuild aborts rather than guess a cmdline, since a wrong
// root=/rd.luks.* would produce an unbootable UKI.
type ErrKernelCmdlineUnavailable struct {
	Path  string
	Cause error
}

func (e *ErrKernelCmdlineUnavailable) Error() string {
	return fmt.Sprintf("uki-rebuild: kernel cmdline unavailable at %s: %v", e.Path, e.Cause)
}

func (e *ErrKernelCmdlineUnavailable) Unwrap() error { return e.Cause }

// ErrNoKernelModules is returned when no installed kernel can be discovered under
// the modules directory.
type ErrNoKernelModules struct {
	ModulesDir string
	Cause      error
}

func (e *ErrNoKernelModules) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("uki-rebuild: no installed kernels under %s: %v", e.ModulesDir, e.Cause)
	}
	return fmt.Sprintf("uki-rebuild: no installed kernels under %s", e.ModulesDir)
}

func (e *ErrNoKernelModules) Unwrap() error { return e.Cause }

// ErrModulesUnsigned is returned by the post-rebuild spot check when none of the
// sampled kernel modules carry a signature. Under CONFIG_MODULE_SIG_FORCE that
// kernel cannot load its modules, so the rebuild refuses to swap to it.
type ErrModulesUnsigned struct {
	Dir     string
	Sampled int
}

func (e *ErrModulesUnsigned) Error() string {
	return fmt.Sprintf("uki-rebuild: none of %d sampled kernel modules under %s are signed; refusing to swap to a kernel whose modules cannot load under CONFIG_MODULE_SIG_FORCE",
		e.Sampled, e.Dir)
}

// ErrUKIRebuildVerify is returned when the rebuilt+signed UKI fails verification
// against the Secure Boot DB certificate before the atomic swap. The live UKI is
// left untouched.
type ErrUKIRebuildVerify struct {
	Path  string
	Cause error
}

func (e *ErrUKIRebuildVerify) Error() string {
	return fmt.Sprintf("uki-rebuild: rebuilt UKI at %s failed Secure Boot verification (not swapped): %v", e.Path, e.Cause)
}

func (e *ErrUKIRebuildVerify) Unwrap() error { return e.Cause }
