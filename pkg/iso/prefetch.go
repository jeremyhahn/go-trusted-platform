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
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer/alpine"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// ErrPreFetchFailed indicates a pre-fetch operation failed.
type ErrPreFetchFailed struct {
	Operation string
	Reason    string
	Err       error
}

func (e *ErrPreFetchFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("pre-fetch %s failed: %s: %v", e.Operation, e.Reason, e.Err)
	}
	return fmt.Sprintf("pre-fetch %s failed: %s", e.Operation, e.Reason)
}

func (e *ErrPreFetchFailed) Unwrap() error {
	return e.Err
}

// ErrPackageNotFound indicates a package was not found in the repository.
type ErrPackageNotFound struct {
	Package string
}

func (e *ErrPackageNotFound) Error() string {
	return fmt.Sprintf("package not found: %s", e.Package)
}

// ErrAPKINDEXFailed indicates APKINDEX generation or retrieval failed.
type ErrAPKINDEXFailed struct {
	Repository string
	Err        error
}

func (e *ErrAPKINDEXFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("APKINDEX operation failed for repository %s: %v", e.Repository, e.Err)
	}
	return fmt.Sprintf("APKINDEX operation failed for repository %s", e.Repository)
}

func (e *ErrAPKINDEXFailed) Unwrap() error {
	return e.Err
}

// PreFetchConfig holds configuration for pre-fetching packages.
type PreFetchConfig struct {
	Mirror       string // Alpine mirror URL
	Version      string // Alpine version (e.g., "3.22.2")
	Architecture string // Architecture (e.g., "x86_64")
	WorkDir      string // Work directory for downloads
	ISODir       string // ISO directory where packages will be placed

	// Feature flags from ISOBuildConfig
	FIPS          bool
	EnableFIDO2   bool
	FilesystemLVM bool
	IMAEnabled    bool

	// IMA audit logging flag
	IMAAuditEnabled bool

	// User-specified additional packages
	ExtraPackages []string
}

// apkPackageEntry represents a parsed package entry from APKINDEX.
type apkPackageEntry struct {
	Name         string
	Version      string
	Architecture string
	Size         int64
	Checksum     string
	Dependencies []string
	Provides     []string
}

// PreFetchBuilder handles pre-fetching of APK packages for air-gapped installation.
type PreFetchBuilder struct {
	config     *PreFetchConfig
	apkManager *alpine.APKManager
	logger     *logging.Logger

	// Cached package index (package name -> entry)
	packageIndex map[string]*apkPackageEntry
}

// NewPreFetchBuilder creates a new PreFetchBuilder.
func NewPreFetchBuilder(config *PreFetchConfig, logger *logging.Logger) *PreFetchBuilder {
	return &PreFetchBuilder{
		config:       config,
		apkManager:   alpine.NewAPKManager(config.Mirror, config.Version, config.Architecture, config.WorkDir, nil),
		logger:       logger,
		packageIndex: make(map[string]*apkPackageEntry),
	}
}

// CollectRequiredPackages returns the list of all packages needed for installation
// based on the provided configuration.
func CollectRequiredPackages(config *PreFetchConfig) []string {
	packages := []string{
		// Base packages
		"alpine-base",
		"e2fsprogs",
		"e2fsprogs-extra",
		"dosfstools",
		"device-mapper",
		"device-mapper-udev",
		"dracut",
		"dracut-modules-network",
		"musl-fts",
		"binutils",
		"systemd-efistub",
		"kmod",
		"gcompat",
		"libc6-compat",
		"ca-certificates",

		// Autoinstall packages (must be available offline)
		"parted",
		"util-linux",
		"eudev",
		"openssl-dev",
	}

	// Add kernel only if NOT in FIPS mode
	// When FIPS is enabled, we use a custom-built FIPS kernel instead
	if !config.FIPS {
		packages = append(packages, "linux-lts")
	}

	// Add LVM packages if filesystem type is LVM
	if config.FilesystemLVM {
		packages = append(packages, "lvm2", "lvm2-openrc")
	}

	// Add FIDO2 packages if FIDO2 support is enabled
	if config.EnableFIDO2 {
		packages = append(packages,
			"libfido2",
			"fido2",
			"coreutils",
		)
	}

	// Add IMA packages if IMA is enabled
	if config.IMAEnabled {
		packages = append(packages,
			"ima-evm-utils",
			"keyutils",
			"attr",
		)

		// Add audit packages if IMA audit logging is enabled
		if config.IMAAuditEnabled {
			packages = append(packages, "audit", "audit-openrc")
		}
	}

	// Add user-specified extra packages
	packages = append(packages, config.ExtraPackages...)

	return packages
}

// BuildLocalRepository downloads all packages and creates a local APK repository in the ISO.
func (b *PreFetchBuilder) BuildLocalRepository(ctx context.Context) error {
	b.logger.Info("[PREFETCH] Starting local repository build",
		"mirror", b.config.Mirror,
		"version", b.config.Version,
		"arch", b.config.Architecture)

	// Collect all required packages
	packages := CollectRequiredPackages(b.config)
	b.logger.Info("[PREFETCH] Collected required packages", "count", len(packages))

	// Download and parse APKINDEX to resolve dependencies
	if err := b.loadPackageIndex(ctx); err != nil {
		return &ErrPreFetchFailed{
			Operation: "load_index",
			Reason:    "failed to load package index",
			Err:       err,
		}
	}

	// Resolve all dependencies
	allPackages, err := b.resolveAllDependencies(packages)
	if err != nil {
		return &ErrPreFetchFailed{
			Operation: "resolve_dependencies",
			Reason:    "failed to resolve package dependencies",
			Err:       err,
		}
	}
	b.logger.Info("[PREFETCH] Resolved all dependencies", "total_packages", len(allPackages))

	// Create directory structure: isoDir/apks-prefetch/{arch}/
	// Use a separate directory to avoid overwriting the Alpine base repository at apks/{arch}/
	packagesDir := filepath.Join(b.config.ISODir, "apks-prefetch", b.config.Architecture)
	if err := os.MkdirAll(packagesDir, 0755); err != nil {
		return &ErrPreFetchFailed{
			Operation: "create_directory",
			Reason:    fmt.Sprintf("failed to create packages directory: %s", packagesDir),
			Err:       err,
		}
	}

	// Download all packages
	if err := b.downloadPackages(ctx, allPackages, packagesDir); err != nil {
		return &ErrPreFetchFailed{
			Operation: "download_packages",
			Reason:    "failed to download packages",
			Err:       err,
		}
	}

	// Generate APKINDEX.tar.gz
	if err := b.GenerateAPKINDEX(ctx, packagesDir); err != nil {
		return &ErrPreFetchFailed{
			Operation: "generate_apkindex",
			Reason:    "failed to generate APKINDEX",
			Err:       err,
		}
	}

	b.logger.Info("[PREFETCH] Local repository build complete",
		"packages_dir", packagesDir,
		"total_packages", len(allPackages))

	return nil
}

// GenerateAPKINDEX creates APKINDEX.tar.gz from downloaded packages.
func (b *PreFetchBuilder) GenerateAPKINDEX(ctx context.Context, packagesDir string) error {
	b.logger.Info("[PREFETCH] Generating APKINDEX.tar.gz", "dir", packagesDir)

	// Collect all APK files in the directory
	apkFiles, err := filepath.Glob(filepath.Join(packagesDir, "*.apk"))
	if err != nil {
		return &ErrAPKINDEXFailed{
			Repository: packagesDir,
			Err:        err,
		}
	}

	if len(apkFiles) == 0 {
		return &ErrAPKINDEXFailed{
			Repository: packagesDir,
			Err:        fmt.Errorf("no APK files found in %s", packagesDir),
		}
	}

	// Build APKINDEX content
	var indexContent strings.Builder
	for _, apkFile := range apkFiles {
		select {
		case <-ctx.Done():
			return &ErrPreFetchFailed{
				Operation: "generate_apkindex",
				Reason:    "context cancelled",
				Err:       ctx.Err(),
			}
		default:
		}

		entry, err := b.extractPackageMetadata(apkFile)
		if err != nil {
			b.logger.Warn("[PREFETCH] Failed to extract metadata from package",
				"file", apkFile, "error", err)
			continue
		}

		// Write package entry in APKINDEX format
		fmt.Fprintf(&indexContent, "C:%s\n", entry.Checksum)
		fmt.Fprintf(&indexContent, "P:%s\n", entry.Name)
		fmt.Fprintf(&indexContent, "V:%s\n", entry.Version)
		fmt.Fprintf(&indexContent, "A:%s\n", entry.Architecture)
		fmt.Fprintf(&indexContent, "S:%d\n", entry.Size)
		fmt.Fprintf(&indexContent, "I:%d\n", entry.Size)
		fmt.Fprintf(&indexContent, "T:%s\n", entry.Name)
		if len(entry.Dependencies) > 0 {
			fmt.Fprintf(&indexContent, "D:%s\n", strings.Join(entry.Dependencies, " "))
		}
		if len(entry.Provides) > 0 {
			fmt.Fprintf(&indexContent, "p:%s\n", strings.Join(entry.Provides, " "))
		}
		indexContent.WriteString("\n") // Empty line separates packages
	}

	// Create APKINDEX.tar.gz
	apkIndexPath := filepath.Join(packagesDir, "APKINDEX.tar.gz")
	outFile, err := os.Create(apkIndexPath)
	if err != nil {
		return &ErrAPKINDEXFailed{
			Repository: packagesDir,
			Err:        err,
		}
	}
	defer outFile.Close()

	gzWriter := gzip.NewWriter(outFile)
	defer gzWriter.Close()

	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	// Write APKINDEX file
	indexBytes := []byte(indexContent.String())
	header := &tar.Header{
		Name:    "APKINDEX",
		Size:    int64(len(indexBytes)),
		Mode:    0644,
		ModTime: time.Now(),
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		return &ErrAPKINDEXFailed{
			Repository: packagesDir,
			Err:        err,
		}
	}

	if _, err := tarWriter.Write(indexBytes); err != nil {
		return &ErrAPKINDEXFailed{
			Repository: packagesDir,
			Err:        err,
		}
	}

	b.logger.Info("[PREFETCH] APKINDEX.tar.gz generated successfully",
		"path", apkIndexPath,
		"packages", len(apkFiles))

	return nil
}

// loadPackageIndex downloads and parses APKINDEX from the main repository.
func (b *PreFetchBuilder) loadPackageIndex(ctx context.Context) error {
	b.logger.Info("[PREFETCH] Loading package index from mirror")

	// Download APKINDEX for main repository
	mainIndexURL := fmt.Sprintf("%s/v%s/main/%s/APKINDEX.tar.gz",
		b.config.Mirror, b.config.Version, b.config.Architecture)

	if err := b.downloadAndParseIndex(ctx, mainIndexURL); err != nil {
		return &ErrAPKINDEXFailed{
			Repository: "main",
			Err:        err,
		}
	}

	// Download APKINDEX for community repository
	communityIndexURL := fmt.Sprintf("%s/v%s/community/%s/APKINDEX.tar.gz",
		b.config.Mirror, b.config.Version, b.config.Architecture)

	if err := b.downloadAndParseIndex(ctx, communityIndexURL); err != nil {
		b.logger.Warn("[PREFETCH] Failed to load community repository index",
			"error", err)
		// Continue without community repo - not all packages may be available
	}

	b.logger.Info("[PREFETCH] Package index loaded", "packages", len(b.packageIndex))

	return nil
}

// downloadAndParseIndex downloads and parses a single APKINDEX file.
func (b *PreFetchBuilder) downloadAndParseIndex(ctx context.Context, indexURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, indexURL, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download APKINDEX: HTTP %d", resp.StatusCode)
	}

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if header.Name == "APKINDEX" {
			return b.parseAPKINDEXContent(tarReader)
		}
	}

	return fmt.Errorf("APKINDEX file not found in archive")
}

// parseAPKINDEXContent parses the APKINDEX content and populates the package index.
func (b *PreFetchBuilder) parseAPKINDEXContent(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	var current *apkPackageEntry

	for scanner.Scan() {
		line := scanner.Text()

		// Empty line indicates end of package entry
		if line == "" {
			if current != nil && current.Name != "" {
				b.packageIndex[current.Name] = current
			}
			current = nil
			continue
		}

		if len(line) < 2 {
			continue
		}

		key := line[0]
		value := line[2:]

		if current == nil {
			current = &apkPackageEntry{}
		}

		switch key {
		case 'P': // Package name
			current.Name = value
		case 'V': // Version
			current.Version = value
		case 'A': // Architecture
			current.Architecture = value
		case 'S': // Package size
			var size int64
			fmt.Sscanf(value, "%d", &size)
			current.Size = size
		case 'C': // Checksum
			current.Checksum = value
		case 'D': // Dependencies
			deps := strings.Fields(value)
			for _, dep := range deps {
				// Strip version constraints (e.g., "foo>=1.0" -> "foo")
				depName := stripVersionConstraint(dep)
				if depName != "" && !strings.HasPrefix(depName, "!") {
					current.Dependencies = append(current.Dependencies, depName)
				}
			}
		case 'p': // Provides
			provides := strings.Fields(value)
			for _, prov := range provides {
				provName := stripVersionConstraint(prov)
				if provName != "" {
					current.Provides = append(current.Provides, provName)
				}
			}
		}
	}

	// Handle last entry
	if current != nil && current.Name != "" {
		b.packageIndex[current.Name] = current
	}

	return scanner.Err()
}

// stripVersionConstraint removes version constraints from dependency names.
// For example: "foo>=1.0" -> "foo", "bar<2.0" -> "bar"
func stripVersionConstraint(dep string) string {
	// Handle negation
	if strings.HasPrefix(dep, "!") {
		return ""
	}

	// Find first version operator
	for i, c := range dep {
		if c == '>' || c == '<' || c == '=' || c == '~' {
			return dep[:i]
		}
	}
	return dep
}

// resolveAllDependencies resolves all dependencies for the given packages.
func (b *PreFetchBuilder) resolveAllDependencies(packages []string) ([]string, error) {
	resolved := make(map[string]bool)
	visited := make(map[string]bool)

	var resolve func(pkgName string) error
	resolve = func(pkgName string) error {
		// Check if already resolved or being visited (cycle detection)
		if resolved[pkgName] {
			return nil
		}
		if visited[pkgName] {
			// Cycle detected, but we allow it (just stop recursion)
			return nil
		}
		visited[pkgName] = true

		// Find package in index
		pkg := b.findPackage(pkgName)
		if pkg == nil {
			b.logger.Warn("[PREFETCH] Package not found in index, skipping",
				"package", pkgName)
			return nil
		}

		// Resolve dependencies first
		for _, dep := range pkg.Dependencies {
			if err := resolve(dep); err != nil {
				return err
			}
		}

		resolved[pkgName] = true
		return nil
	}

	// Resolve each requested package
	for _, pkg := range packages {
		if err := resolve(pkg); err != nil {
			return nil, err
		}
	}

	// Convert map to sorted slice
	result := make([]string, 0, len(resolved))
	for pkg := range resolved {
		result = append(result, pkg)
	}
	sort.Strings(result)

	return result, nil
}

// findPackage finds a package by name, checking direct name and provides.
func (b *PreFetchBuilder) findPackage(name string) *apkPackageEntry {
	// Direct lookup
	if pkg, ok := b.packageIndex[name]; ok {
		return pkg
	}

	// Check provides
	for _, pkg := range b.packageIndex {
		for _, provides := range pkg.Provides {
			if provides == name {
				return pkg
			}
		}
	}

	return nil
}

// downloadPackages downloads all packages to the specified directory.
func (b *PreFetchBuilder) downloadPackages(ctx context.Context, packages []string, destDir string) error {
	b.logger.Info("[PREFETCH] Downloading packages", "count", len(packages), "dest", destDir)

	downloaded := 0
	for _, pkgName := range packages {
		select {
		case <-ctx.Done():
			return &ErrPreFetchFailed{
				Operation: "download_packages",
				Reason:    "context cancelled",
				Err:       ctx.Err(),
			}
		default:
		}

		pkg := b.findPackage(pkgName)
		if pkg == nil {
			b.logger.Warn("[PREFETCH] Package not found, skipping", "package", pkgName)
			continue
		}

		if err := b.downloadPackage(ctx, pkg, destDir); err != nil {
			return &ErrPreFetchFailed{
				Operation: "download_package",
				Reason:    fmt.Sprintf("failed to download %s", pkgName),
				Err:       err,
			}
		}

		downloaded++
		if downloaded%10 == 0 {
			b.logger.Info("[PREFETCH] Download progress",
				"downloaded", downloaded,
				"total", len(packages))
		}
	}

	b.logger.Info("[PREFETCH] All packages downloaded", "count", downloaded)
	return nil
}

// downloadPackage downloads a single package to the destination directory.
func (b *PreFetchBuilder) downloadPackage(ctx context.Context, pkg *apkPackageEntry, destDir string) error {
	filename := fmt.Sprintf("%s-%s.apk", pkg.Name, pkg.Version)
	destPath := filepath.Join(destDir, filename)

	// Check if already downloaded
	if _, err := os.Stat(destPath); err == nil {
		b.logger.Debug("[PREFETCH] Package already exists, skipping",
			"package", pkg.Name)
		return nil
	}

	// Try main repository first, then community
	repos := []string{"main", "community"}
	var lastErr error

	for _, repo := range repos {
		url := fmt.Sprintf("%s/v%s/%s/%s/%s",
			b.config.Mirror, b.config.Version, repo, b.config.Architecture, filename)

		if err := b.downloadFile(ctx, url, destPath); err != nil {
			lastErr = err
			continue
		}

		b.logger.Debug("[PREFETCH] Downloaded package",
			"package", pkg.Name,
			"version", pkg.Version,
			"repo", repo)
		return nil
	}

	return lastErr
}

// downloadFile downloads a file from URL to the specified path.
func (b *PreFetchBuilder) downloadFile(ctx context.Context, url, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, url)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// extractPackageMetadata extracts metadata from an APK file.
func (b *PreFetchBuilder) extractPackageMetadata(apkPath string) (*apkPackageEntry, error) {
	f, err := os.Open(apkPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Get file info for size
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	// Calculate checksum
	hasher := sha1.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return nil, err
	}
	checksum := "Q1" + base64.StdEncoding.EncodeToString(hasher.Sum(nil))

	// Reset file position
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	// APK files are gzipped tar archives
	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	entry := &apkPackageEntry{
		Size:     info.Size(),
		Checksum: checksum,
	}

	// Look for .PKGINFO file
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if header.Name == ".PKGINFO" {
			if err := b.parsePKGINFO(tarReader, entry); err != nil {
				return nil, err
			}
			break
		}
	}

	// If we couldn't parse PKGINFO, try to extract info from filename
	if entry.Name == "" {
		base := filepath.Base(apkPath)
		base = strings.TrimSuffix(base, ".apk")

		// Find last hyphen that's followed by a digit (version separator)
		lastIdx := -1
		for i := len(base) - 1; i >= 0; i-- {
			if base[i] == '-' && i+1 < len(base) && base[i+1] >= '0' && base[i+1] <= '9' {
				lastIdx = i
				break
			}
		}

		if lastIdx > 0 {
			entry.Name = base[:lastIdx]
			entry.Version = base[lastIdx+1:]
		} else {
			entry.Name = base
			entry.Version = "unknown"
		}
		entry.Architecture = b.config.Architecture
	}

	return entry, nil
}

// parsePKGINFO parses the .PKGINFO file content.
func (b *PreFetchBuilder) parsePKGINFO(r io.Reader, entry *apkPackageEntry) error {
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		parts := strings.SplitN(line, " = ", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := parts[1]

		switch key {
		case "pkgname":
			entry.Name = value
		case "pkgver":
			entry.Version = value
		case "arch":
			entry.Architecture = value
		case "depend":
			depName := stripVersionConstraint(value)
			if depName != "" && !strings.HasPrefix(depName, "!") {
				entry.Dependencies = append(entry.Dependencies, depName)
			}
		case "provides":
			provName := stripVersionConstraint(value)
			if provName != "" {
				entry.Provides = append(entry.Provides, provName)
			}
		}
	}

	return scanner.Err()
}
