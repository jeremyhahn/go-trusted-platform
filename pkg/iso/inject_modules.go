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

package iso

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// desiredNetworkModules is the candidate set of NIC driver modules injected
// into the initramfs. Only modules that actually exist in the modloop squashfs
// for the target kernel are injected; the rest are skipped (logged, not fatal).
//
// The list covers the Intel parts on the Supermicro X10 fleet (igb for i210
// 0x1533 / i350 0x1521, ixgbe for X552 10GbE 0x15ac) plus the common Intel,
// Broadcom, Mellanox, Realtek and Aquantia NICs found on bare-metal hardware
// the platform provisions, so a PXE-booted node can DHCP regardless of vendor.
var desiredNetworkModules = []string{
	"igb", "igc", "ixgbe", "i40e", "ice",
	"e1000", "e1000e", "tg3", "bnx2", "bnx2x",
	"bnxt_en", "mlx4_en", "mlx5_core", "r8169", "atlantic",
	// af_packet (AF_PACKET / PF_PACKET) is required by udhcpc and any raw
	// L2 socket user. Without it the initramfs DHCP client fails with
	// "socket(AF_PACKET,...): Address family not supported by protocol",
	// so even with a NIC driver + link up the modloop fetch never gets an
	// IP and the node drops to the rescue shell.
	"af_packet",
}

// injectNetworkModules copies NIC driver kernel modules (and their full
// dependency closure) out of the ISO's modloop squashfs and into the extracted
// initramfs tree, then regenerates the initramfs module metadata with depmod so
// Alpine's nlplug-findfs can autoload the right driver by PCI alias at boot.
//
// Why this exists — the boot-time deadlock it resolves:
//
// A PXE-booted node's firmware fetches only the kernel and the initramfs. The
// Alpine initramfs ships with almost no NIC drivers; the real driver set lives
// in the modloop squashfs (boot/modloop-lts), which the initramfs is supposed
// to fetch over HTTP via the modloop= kernel arg. But fetching modloop requires
// a working network interface, and bringing up the interface requires the NIC
// driver — which is inside the modloop that hasn't been fetched yet. The result
// observed on real X10 hardware: /sys/class/net shows only lo, ip=dhcp no-ops,
// the modloop fetch fails, and the node drops to the Alpine emergency shell.
//
// We break the cycle by pre-staging the NIC drivers directly into the initramfs
// at ISO-build time, where modloop is available locally and uncompressed. With
// the drivers and a depmod-generated modules.dep/modules.alias present in the
// initramfs, the kernel autoloads the NIC by PCI alias, ip=dhcp succeeds, and
// the modloop fetch (for everything else) then works over the configured link.
//
// It is called from ModifyInitramfs after extractInitramfs has populated tmpDir
// and before repackInitramfs re-archives it.
func (c *Customizer) injectNetworkModules(ctx context.Context, tmpDir string) error {
	// 1. Locate the modloop squashfs alongside the initramfs in the ISO root.
	modloopPath := filepath.Join(c.config.Directories.ISO, "boot", "modloop-lts")
	if _, err := os.Stat(modloopPath); err != nil {
		return ErrModloopNotFound(modloopPath, err)
	}

	// 2. Determine the kernel version: the single directory under
	//    <tmpDir>/lib/modules. Refuse to guess if it is ambiguous.
	modulesRoot := filepath.Join(tmpDir, "lib", "modules")
	entries, err := os.ReadDir(modulesRoot)
	if err != nil {
		return ErrInitramfsModulesDir(modulesRoot, err)
	}
	var kvers []string
	for _, e := range entries {
		if e.IsDir() {
			kvers = append(kvers, e.Name())
		}
	}
	if len(kvers) != 1 {
		return ErrKernelVersionAmbiguous(modulesRoot, len(kvers))
	}
	kver := kvers[0]

	// 3. unsquashfs the modloop into a scratch dir under Work (cleaned up).
	unsquashDir, err := os.MkdirTemp(c.config.Directories.Work, "modloop-")
	if err != nil {
		return ErrModloopExtractDir(err)
	}
	defer os.RemoveAll(unsquashDir)

	// MkdirTemp already created unsquashDir, so -f forces unsquashfs to write
	// into the existing directory rather than aborting.
	unsquashCmd := exec.CommandContext(ctx, "unsquashfs", "-f", "-d", unsquashDir, modloopPath)
	if out, err := unsquashCmd.CombinedOutput(); err != nil {
		return ErrModloopUnsquash(modloopPath, err, string(out))
	}

	// The same kernel version must exist inside modloop (modules/<kver>),
	// otherwise the drivers we copy won't match the running kernel.
	modloopKverDir := filepath.Join(unsquashDir, "modules", kver)
	if _, err := os.Stat(modloopKverDir); err != nil {
		return ErrModloopKernelMismatch(kver, err)
	}

	// 4. Parse modloop's modules.dep and resolve the full dependency closure
	//    of the desired NIC drivers. Missing drivers are skipped, not fatal.
	depPath := filepath.Join(modloopKverDir, "modules.dep")
	depData, err := os.ReadFile(depPath)
	if err != nil {
		return ErrModulesDepRead(depPath, err)
	}

	closure, err := resolveModuleDeps(string(depData), desiredNetworkModules)
	if err != nil {
		return ErrModuleDepResolve(err)
	}

	// Report which requested drivers were absent from this modloop.
	present := make(map[string]bool, len(closure))
	for _, rel := range closure {
		present[normalizeModuleName(moduleName(rel))] = true
	}
	var skipped []string
	for _, want := range desiredNetworkModules {
		if !present[normalizeModuleName(want)] {
			skipped = append(skipped, want)
		}
	}
	if len(skipped) > 0 {
		c.logger.Info("Skipping NIC modules not present in modloop",
			"kver", kver,
			"modules", strings.Join(skipped, ","))
	}

	// 5. Copy every resolved module into the initramfs, preserving the path
	//    relative to the kver dir and skipping files already present.
	destKverDir := filepath.Join(tmpDir, "lib", "modules", kver)
	var injected []string
	for _, rel := range closure {
		dst := filepath.Join(destKverDir, rel)
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		src := filepath.Join(modloopKverDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return ErrModuleCopy(rel, err)
		}
		if err := copyFile(src, dst); err != nil {
			return ErrModuleCopy(rel, err)
		}
		injected = append(injected, moduleName(rel))
	}

	// 6. Copy depmod input metadata if present (missing is non-fatal). depmod
	//    consumes these to account for built-in modules when resolving deps.
	for _, meta := range []string{"modules.builtin", "modules.builtin.modinfo", "modules.order"} {
		src := filepath.Join(modloopKverDir, meta)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(destKverDir, meta)
		if err := copyFile(src, dst); err != nil {
			c.logger.Warn("Failed to copy module metadata file", "file", meta, "error", err)
		}
	}

	// 7. Regenerate modules.dep/modules.alias/etc. inside the initramfs so the
	//    kernel's autoloader can map a PCI ID to the injected driver. A depmod
	//    failure leaves the initramfs unable to autoload — treat it as fatal.
	depmodCmd := exec.CommandContext(ctx, "depmod", "-b", tmpDir, kver)
	if out, err := depmodCmd.CombinedOutput(); err != nil {
		return ErrDepmod(kver, err, string(out))
	}

	// 8. Report what was injected.
	c.logger.Info("Injected NIC kernel modules into initramfs",
		"count", len(injected),
		"kver", kver,
		"modules", strings.Join(injected, ","))

	return nil
}

// resolveModuleDeps parses the contents of a kernel modules.dep file and
// returns the full, transitive dependency closure of the wanted modules as
// paths relative to the modules/<kver> directory (e.g.
// "kernel/drivers/net/ethernet/intel/igb/igb.ko").
//
// modules.dep has one entry per line in the form:
//
//	kernel/path/mod.ko: dep1.ko dep2.ko ...
//
// where every path is relative to modules/<kver>/ and a module with no
// dependencies still appears as "path:". Wanted modules are matched by their
// base name (the filename minus any .ko/.ko.gz/.ko.xz/.ko.zst suffix), with
// '-' and '_' treated as interchangeable the way modprobe does. A wanted
// module that is absent from the dep file is skipped silently — it is the
// caller's job to log skipped modules. The result is sorted for determinism.
//
// The function is pure (no filesystem or exec access) so the dependency-closure
// logic can be unit-tested without a real squashfs or depmod.
func resolveModuleDeps(depFileContents string, wanted []string) ([]string, error) {
	deps := make(map[string][]string) // module path -> direct dependency paths
	byName := make(map[string]string) // normalized module name -> module path

	for _, line := range strings.Split(depFileContents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		modPath := strings.TrimSpace(line[:idx])
		if modPath == "" {
			continue
		}
		var direct []string
		if rest := strings.TrimSpace(line[idx+1:]); rest != "" {
			direct = strings.Fields(rest)
		}
		deps[modPath] = direct
		byName[normalizeModuleName(moduleName(modPath))] = modPath
	}

	seen := make(map[string]bool)
	var closure []string
	var visit func(path string)
	visit = func(path string) {
		if seen[path] {
			return
		}
		seen[path] = true
		closure = append(closure, path)
		for _, dep := range deps[path] {
			visit(dep)
		}
	}

	for _, want := range wanted {
		if path, ok := byName[normalizeModuleName(want)]; ok {
			visit(path)
		}
	}

	sort.Strings(closure)
	return closure, nil
}

// moduleName returns the bare module name for a modules.dep path or filename by
// stripping the directory and any compressed-module suffix.
func moduleName(path string) string {
	base := filepath.Base(path)
	for _, ext := range []string{".ko.gz", ".ko.xz", ".ko.zst", ".ko.zstd", ".ko"} {
		if strings.HasSuffix(base, ext) {
			return strings.TrimSuffix(base, ext)
		}
	}
	return base
}

// normalizeModuleName canonicalizes a module name so that '-' and '_' compare
// equal, matching modprobe/depmod alias behavior.
func normalizeModuleName(name string) string {
	return strings.ReplaceAll(name, "-", "_")
}
