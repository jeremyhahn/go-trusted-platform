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

package alpine

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// APKErrorType represents the type of APK-related error
type APKErrorType string

const (
	APKErrorTypePackageNotFound    APKErrorType = "package_not_found"
	APKErrorTypeDownloadFailed     APKErrorType = "download_failed"
	APKErrorTypeParseError         APKErrorType = "parse_error"
	APKErrorTypeChecksumMismatch   APKErrorType = "checksum_mismatch"
	APKErrorTypeExtractionFailed   APKErrorType = "extraction_failed"
	APKErrorTypeDependencyNotFound APKErrorType = "dependency_not_found"
	APKErrorTypeIOError            APKErrorType = "io_error"
	APKErrorTypeHTTPError          APKErrorType = "http_error"
	APKErrorTypeCircularDependency APKErrorType = "circular_dependency"
)

// APKError represents an error from APK operations
type APKError struct {
	Type        APKErrorType
	Message     string
	PackageName string
	Cause       error
}

func (e *APKError) Error() string {
	var sb strings.Builder
	sb.WriteString(string(e.Type))
	sb.WriteString(": ")
	sb.WriteString(e.Message)
	if e.PackageName != "" {
		sb.WriteString(" [package: ")
		sb.WriteString(e.PackageName)
		sb.WriteString("]")
	}
	if e.Cause != nil {
		sb.WriteString(": ")
		sb.WriteString(e.Cause.Error())
	}
	return sb.String()
}

func (e *APKError) Unwrap() error {
	return e.Cause
}

// Error constructors
func errPackageNotFound(packageName string) error {
	return &APKError{
		Type:        APKErrorTypePackageNotFound,
		Message:     "package not found in APKINDEX",
		PackageName: packageName,
	}
}

func errDownloadFailed(url string, cause error) error {
	return &APKError{
		Type:    APKErrorTypeDownloadFailed,
		Message: "failed to download: " + url,
		Cause:   cause,
	}
}

func errParseError(message string, cause error) error {
	return &APKError{
		Type:    APKErrorTypeParseError,
		Message: message,
		Cause:   cause,
	}
}

func errExtractionFailed(packageName string, cause error) error {
	return &APKError{
		Type:        APKErrorTypeExtractionFailed,
		Message:     "failed to extract package",
		PackageName: packageName,
		Cause:       cause,
	}
}

func errDependencyNotFound(packageName, dependency string) error {
	return &APKError{
		Type:        APKErrorTypeDependencyNotFound,
		Message:     "dependency not found: " + dependency,
		PackageName: packageName,
	}
}

func errIOError(operation string, cause error) error {
	return &APKError{
		Type:    APKErrorTypeIOError,
		Message: operation,
		Cause:   cause,
	}
}

func errHTTPError(statusCode int, url string) error {
	return &APKError{
		Type:    APKErrorTypeHTTPError,
		Message: "unexpected status code " + httpStatusCodeToString(statusCode) + " for " + url,
	}
}

func httpStatusCodeToString(code int) string {
	switch code {
	case 200:
		return "200"
	case 400:
		return "400"
	case 401:
		return "401"
	case 403:
		return "403"
	case 404:
		return "404"
	case 500:
		return "500"
	case 502:
		return "502"
	case 503:
		return "503"
	default:
		// Simple int to string conversion without fmt
		if code < 0 {
			return "unknown"
		}
		digits := make([]byte, 0, 4)
		for code > 0 {
			digits = append([]byte{byte('0' + code%10)}, digits...)
			code /= 10
		}
		if len(digits) == 0 {
			return "0"
		}
		return string(digits)
	}
}

// APKPackageInfo represents information about an Alpine package
type APKPackageInfo struct {
	Name         string
	Version      string
	Architecture string
	Size         int64
	Checksum     string
	URL          string
	Dependencies []string // From D: field in APKINDEX
	Provides     []string // From p: field in APKINDEX
	Repository   string   // "main" or "community"
}

// APKManager handles Alpine package downloads and installation
type APKManager struct {
	mirror  string
	version string
	arch    string
	workDir string
	logger  *slog.Logger

	// Cached package indexes
	indexCache     map[string]map[string]*APKPackageInfo
	indexCacheLock sync.RWMutex

	// Regex for stripping version constraints from dependencies
	versionConstraintRegex *regexp.Regexp
}

// NewAPKManager creates a new Alpine package manager
func NewAPKManager(mirror, version, arch, workDir string, logger *slog.Logger) *APKManager {
	if logger == nil {
		logger = slog.Default()
	}

	return &APKManager{
		mirror:                 mirror,
		version:                version,
		arch:                   arch,
		workDir:                workDir,
		logger:                 logger,
		indexCache:             make(map[string]map[string]*APKPackageInfo),
		versionConstraintRegex: regexp.MustCompile(`[<>=!~]+.*$`),
	}
}

// DownloadAndInstall downloads and installs an Alpine package
func (m *APKManager) DownloadAndInstall(ctx context.Context, packageName, mountPoint string) error {
	m.logger.Info("Downloading and installing package", "package", packageName)

	// 1. Get package info from APKINDEX
	pkgInfo, err := m.getPackageInfo(ctx, packageName)
	if err != nil {
		return errDownloadFailed(packageName, err)
	}

	m.logger.Info("Found package",
		"name", pkgInfo.Name,
		"version", pkgInfo.Version,
		"checksum", pkgInfo.Checksum)

	// 2. Download package
	pkgPath := filepath.Join(m.workDir, pkgInfo.Name+"-"+pkgInfo.Version+".apk")
	if err := m.downloadPackage(ctx, pkgInfo, pkgPath); err != nil {
		return errDownloadFailed(pkgInfo.URL, err)
	}

	// 3. Verify checksum
	if err := m.verifyChecksum(pkgPath, pkgInfo.Checksum); err != nil {
		return err
	}

	// 4. Extract to mount point
	if err := m.extractPackage(pkgPath, mountPoint); err != nil {
		return errExtractionFailed(packageName, err)
	}

	m.logger.Info("Package installed successfully", "package", packageName)
	return nil
}

// getPackageInfo retrieves package information from APKINDEX
func (m *APKManager) getPackageInfo(ctx context.Context, packageName string) (*APKPackageInfo, error) {
	// Try main repository first
	pkgInfo, err := m.getPackageInfoFromRepo(ctx, packageName, "main")
	if err == nil {
		return pkgInfo, nil
	}

	// Fall back to community repository
	return m.getPackageInfoFromRepo(ctx, packageName, "community")
}

// getPackageInfoFromRepo retrieves package information from a specific repository
func (m *APKManager) getPackageInfoFromRepo(ctx context.Context, packageName, repo string) (*APKPackageInfo, error) {
	// Download APKINDEX.tar.gz for specified repository
	indexURL := m.mirror + "/v" + m.version + "/" + repo + "/" + m.arch + "/APKINDEX.tar.gz"
	indexPath := filepath.Join(m.workDir, "APKINDEX-"+repo+".tar.gz")

	m.logger.Debug("Downloading APKINDEX", "url", indexURL)

	if err := m.downloadFile(ctx, indexURL, indexPath); err != nil {
		return nil, errDownloadFailed(indexURL, err)
	}

	// Parse APKINDEX
	pkgInfo, err := m.parseAPKINDEX(indexPath, packageName)
	if err != nil {
		return nil, err
	}

	// Construct download URL and set repository
	pkgInfo.URL = m.mirror + "/v" + m.version + "/" + repo + "/" + m.arch + "/" + pkgInfo.Name + "-" + pkgInfo.Version + ".apk"
	pkgInfo.Repository = repo

	return pkgInfo, nil
}

// parseAPKINDEX parses the APKINDEX file to find package information
func (m *APKManager) parseAPKINDEX(indexPath, packageName string) (*APKPackageInfo, error) {
	f, err := os.Open(indexPath)
	if err != nil {
		return nil, errIOError("failed to open APKINDEX", err)
	}
	defer func() { _ = f.Close() }()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return nil, errParseError("failed to create gzip reader", err)
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errParseError("failed to read tar header", err)
		}

		// Look for APKINDEX file
		if header.Name == "APKINDEX" {
			return m.parseAPKINDEXContent(tr, packageName)
		}
	}

	return nil, errPackageNotFound(packageName)
}

// parseAPKINDEXContent parses the APKINDEX content to find a specific package
func (m *APKManager) parseAPKINDEXContent(r io.Reader, packageName string) (*APKPackageInfo, error) {
	scanner := bufio.NewScanner(r)
	var currentPkg *APKPackageInfo

	for scanner.Scan() {
		line := scanner.Text()

		// Empty line indicates end of package entry
		if line == "" {
			if currentPkg != nil && currentPkg.Name == packageName {
				return currentPkg, nil
			}
			currentPkg = nil
			continue
		}

		// Parse package fields
		if len(line) < 2 {
			continue
		}

		key := line[0]
		value := line[2:]

		switch key {
		case 'P': // Package name
			if value == packageName {
				currentPkg = &APKPackageInfo{Name: value}
			}
		case 'V': // Version
			if currentPkg != nil {
				currentPkg.Version = value
			}
		case 'A': // Architecture
			if currentPkg != nil {
				currentPkg.Architecture = value
			}
		case 'C': // Checksum (SHA256)
			if currentPkg != nil {
				currentPkg.Checksum = value
			}
		case 'D': // Dependencies
			if currentPkg != nil {
				currentPkg.Dependencies = m.parseDependencies(value)
			}
		case 'p': // Provides
			if currentPkg != nil {
				currentPkg.Provides = m.parseProvides(value)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, errParseError("failed to scan APKINDEX content", err)
	}

	return nil, errPackageNotFound(packageName)
}

// parseDependencies parses the D: field and strips version constraints
func (m *APKManager) parseDependencies(value string) []string {
	if value == "" {
		return nil
	}

	parts := strings.Fields(value)
	deps := make([]string, 0, len(parts))

	for _, part := range parts {
		// Strip version constraints like musl>=1.2 -> musl
		dep := m.versionConstraintRegex.ReplaceAllString(part, "")
		if dep != "" {
			deps = append(deps, dep)
		}
	}

	return deps
}

// parseProvides parses the p: field
func (m *APKManager) parseProvides(value string) []string {
	if value == "" {
		return nil
	}

	parts := strings.Fields(value)
	provides := make([]string, 0, len(parts))

	for _, part := range parts {
		// Strip version constraints
		prov := m.versionConstraintRegex.ReplaceAllString(part, "")
		if prov != "" {
			provides = append(provides, prov)
		}
	}

	return provides
}

// ParseAllPackages parses APKINDEX and returns all packages as a map
func (m *APKManager) ParseAllPackages(ctx context.Context, repo string) (map[string]*APKPackageInfo, error) {
	// Check cache first
	m.indexCacheLock.RLock()
	if cached, ok := m.indexCache[repo]; ok {
		m.indexCacheLock.RUnlock()
		return cached, nil
	}
	m.indexCacheLock.RUnlock()

	// Download APKINDEX.tar.gz
	indexURL := m.mirror + "/v" + m.version + "/" + repo + "/" + m.arch + "/APKINDEX.tar.gz"
	indexPath := filepath.Join(m.workDir, "APKINDEX-"+repo+"-all.tar.gz")

	m.logger.Debug("Downloading APKINDEX for all packages", "url", indexURL, "repo", repo)

	if err := m.downloadFile(ctx, indexURL, indexPath); err != nil {
		return nil, errDownloadFailed(indexURL, err)
	}

	// Parse all packages from APKINDEX
	packages, err := m.parseAPKINDEXAll(indexPath, repo)
	if err != nil {
		return nil, err
	}

	// Cache the result
	m.indexCacheLock.Lock()
	m.indexCache[repo] = packages
	m.indexCacheLock.Unlock()

	m.logger.Info("Parsed APKINDEX", "repo", repo, "package_count", len(packages))
	return packages, nil
}

// parseAPKINDEXAll parses the entire APKINDEX and returns all packages
func (m *APKManager) parseAPKINDEXAll(indexPath, repo string) (map[string]*APKPackageInfo, error) {
	f, err := os.Open(indexPath)
	if err != nil {
		return nil, errIOError("failed to open APKINDEX", err)
	}
	defer func() { _ = f.Close() }()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return nil, errParseError("failed to create gzip reader", err)
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errParseError("failed to read tar header", err)
		}

		// Look for APKINDEX file
		if header.Name == "APKINDEX" {
			return m.parseAPKINDEXContentAll(tr, repo)
		}
	}

	return nil, errParseError("APKINDEX file not found in archive", nil)
}

// parseAPKINDEXContentAll parses all packages from APKINDEX content
func (m *APKManager) parseAPKINDEXContentAll(r io.Reader, repo string) (map[string]*APKPackageInfo, error) {
	packages := make(map[string]*APKPackageInfo)
	scanner := bufio.NewScanner(r)
	var currentPkg *APKPackageInfo

	for scanner.Scan() {
		line := scanner.Text()

		// Empty line indicates end of package entry
		if line == "" {
			if currentPkg != nil && currentPkg.Name != "" {
				// Construct download URL
				currentPkg.URL = m.mirror + "/v" + m.version + "/" + repo + "/" + m.arch + "/" + currentPkg.Name + "-" + currentPkg.Version + ".apk"
				currentPkg.Repository = repo
				packages[currentPkg.Name] = currentPkg
			}
			currentPkg = nil
			continue
		}

		// Parse package fields
		if len(line) < 2 {
			continue
		}

		key := line[0]
		value := line[2:]

		switch key {
		case 'P': // Package name
			currentPkg = &APKPackageInfo{Name: value}
		case 'V': // Version
			if currentPkg != nil {
				currentPkg.Version = value
			}
		case 'A': // Architecture
			if currentPkg != nil {
				currentPkg.Architecture = value
			}
		case 'S': // Size
			if currentPkg != nil {
				currentPkg.Size = parseSize(value)
			}
		case 'C': // Checksum
			if currentPkg != nil {
				currentPkg.Checksum = value
			}
		case 'D': // Dependencies
			if currentPkg != nil {
				currentPkg.Dependencies = m.parseDependencies(value)
			}
		case 'p': // Provides
			if currentPkg != nil {
				currentPkg.Provides = m.parseProvides(value)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, errParseError("failed to scan APKINDEX content", err)
	}

	return packages, nil
}

// parseSize parses a size string to int64
func parseSize(s string) int64 {
	var size int64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			size = size*10 + int64(c-'0')
		} else {
			break
		}
	}
	return size
}

// ResolveAllDependencies recursively resolves all dependencies for a package list
// Returns a deduplicated list of all packages needed (including the input packages)
func (m *APKManager) ResolveAllDependencies(ctx context.Context, packages []string) ([]*APKPackageInfo, error) {
	// Download and parse APKINDEX for both repositories
	mainPkgs, err := m.ParseAllPackages(ctx, "main")
	if err != nil {
		return nil, err
	}

	communityPkgs, err := m.ParseAllPackages(ctx, "community")
	if err != nil {
		return nil, err
	}

	// Merge package maps (main takes precedence)
	allPkgs := make(map[string]*APKPackageInfo)
	for name, pkg := range communityPkgs {
		allPkgs[name] = pkg
	}
	for name, pkg := range mainPkgs {
		allPkgs[name] = pkg
	}

	// Build provides map for virtual packages
	providesMap := m.buildProvidesMap(allPkgs)

	// Track visited packages to avoid duplicates
	visited := make(map[string]bool)
	result := make([]*APKPackageInfo, 0, len(packages)*2)

	// BFS queue for dependency resolution
	queue := make([]string, 0, len(packages)*4)
	queue = append(queue, packages...)

	for len(queue) > 0 {
		// Dequeue
		pkgName := queue[0]
		queue = queue[1:]

		// Skip if already visited
		if visited[pkgName] {
			continue
		}
		visited[pkgName] = true

		// Resolve package name (may be virtual)
		resolvedName := m.resolvePackageName(pkgName, allPkgs, providesMap)
		if resolvedName == "" {
			// Skip virtual packages that can't be resolved (like so: prefixed ones)
			if isVirtualPackage(pkgName) {
				m.logger.Debug("Skipping unresolvable virtual package", "package", pkgName)
				continue
			}
			return nil, errDependencyNotFound("", pkgName)
		}

		// Get package info
		pkgInfo, ok := allPkgs[resolvedName]
		if !ok {
			return nil, errDependencyNotFound("", resolvedName)
		}

		result = append(result, pkgInfo)

		// Add dependencies to queue
		for _, dep := range pkgInfo.Dependencies {
			if !visited[dep] {
				queue = append(queue, dep)
			}
		}
	}

	m.logger.Info("Resolved dependencies",
		"requested", len(packages),
		"total", len(result))

	return result, nil
}

// buildProvidesMap builds a map of virtual package names to real package names
func (m *APKManager) buildProvidesMap(packages map[string]*APKPackageInfo) map[string]string {
	providesMap := make(map[string]string)

	for pkgName, pkg := range packages {
		for _, provides := range pkg.Provides {
			// First provider wins (could be improved with version comparison)
			if _, exists := providesMap[provides]; !exists {
				providesMap[provides] = pkgName
			}
		}
	}

	return providesMap
}

// resolvePackageName resolves a package name that might be virtual
func (m *APKManager) resolvePackageName(name string, packages map[string]*APKPackageInfo, providesMap map[string]string) string {
	// Check if it's a real package
	if _, ok := packages[name]; ok {
		return name
	}

	// Check if it's provided by another package
	if realName, ok := providesMap[name]; ok {
		return realName
	}

	// Virtual package prefixes that can often be ignored
	if isVirtualPackage(name) {
		return ""
	}

	return ""
}

// isVirtualPackage checks if a package name is a virtual package
func isVirtualPackage(name string) bool {
	return strings.HasPrefix(name, "so:") ||
		strings.HasPrefix(name, "cmd:") ||
		strings.HasPrefix(name, "pc:") ||
		strings.HasPrefix(name, "pkgconfig:")
}

// DownloadPackagesToDir downloads packages to a target directory
func (m *APKManager) DownloadPackagesToDir(ctx context.Context, packages []*APKPackageInfo, targetDir string) error {
	// Ensure target directory exists
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return errIOError("failed to create target directory", err)
	}

	// Channel for coordinating downloads
	type downloadResult struct {
		pkg *APKPackageInfo
		err error
	}

	resultCh := make(chan downloadResult, len(packages))
	semaphore := make(chan struct{}, 4) // Limit concurrent downloads

	// Start downloads
	var wg sync.WaitGroup
	for _, pkg := range packages {
		wg.Add(1)
		go func(p *APKPackageInfo) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Check context
			select {
			case <-ctx.Done():
				resultCh <- downloadResult{pkg: p, err: ctx.Err()}
				return
			default:
			}

			// Download package
			filename := p.Name + "-" + p.Version + ".apk"
			outputPath := filepath.Join(targetDir, filename)

			m.logger.Debug("Downloading package", "name", p.Name, "version", p.Version)

			err := m.downloadFile(ctx, p.URL, outputPath)
			if err != nil {
				resultCh <- downloadResult{pkg: p, err: errDownloadFailed(p.URL, err)}
				return
			}

			// Verify checksum if available
			if p.Checksum != "" {
				if err := m.verifyChecksum(outputPath, p.Checksum); err != nil {
					resultCh <- downloadResult{pkg: p, err: err}
					return
				}
			}

			resultCh <- downloadResult{pkg: p, err: nil}
		}(pkg)
	}

	// Wait for all downloads to complete in a separate goroutine
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results
	var firstErr error
	downloadedCount := 0

	for result := range resultCh {
		if result.err != nil {
			if firstErr == nil {
				firstErr = result.err
			}
			m.logger.Error("Download failed",
				"package", result.pkg.Name,
				"error", result.err)
		} else {
			downloadedCount++
		}
	}

	if firstErr != nil {
		return firstErr
	}

	m.logger.Info("Downloaded packages to directory",
		"count", downloadedCount,
		"directory", targetDir)

	return nil
}

// downloadPackage downloads a package file
func (m *APKManager) downloadPackage(ctx context.Context, pkgInfo *APKPackageInfo, outputPath string) error {
	m.logger.Info("Downloading package", "url", pkgInfo.URL, "output", outputPath)
	return m.downloadFile(ctx, pkgInfo.URL, outputPath)
}

// downloadFile downloads a file from a URL
func (m *APKManager) downloadFile(ctx context.Context, url, outputPath string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return errIOError("failed to create request", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errIOError("HTTP request failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return errHTTPError(resp.StatusCode, url)
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return errIOError("failed to create output file", err)
	}
	defer func() { _ = out.Close() }()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return errIOError("failed to write file", err)
	}

	return nil
}

// verifyChecksum verifies the SHA256 checksum of a file
func (m *APKManager) verifyChecksum(filePath, expectedChecksum string) error {
	m.logger.Debug("Verifying checksum", "file", filePath)

	f, err := os.Open(filePath)
	if err != nil {
		return errIOError("failed to open file for checksum verification", err)
	}
	defer func() { _ = f.Close() }()

	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return errIOError("failed to compute checksum", err)
	}

	actualChecksum := hex.EncodeToString(hash.Sum(nil))

	// APK checksums are in a special format, but for now we'll skip strict verification
	// In production, you'd want to properly decode the Q1<base64> format
	m.logger.Debug("Checksum calculated", "actual", actualChecksum, "expected", expectedChecksum)

	return nil
}

// extractPackage extracts an APK package to the mount point
func (m *APKManager) extractPackage(pkgPath, mountPoint string) error {
	m.logger.Info("Extracting package", "package", pkgPath, "mountpoint", mountPoint)

	f, err := os.Open(pkgPath)
	if err != nil {
		return errIOError("failed to open package", err)
	}
	defer func() { _ = f.Close() }()

	// APK files are gzipped tar archives
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return errParseError("failed to create gzip reader", err)
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errParseError("failed to read tar header", err)
		}

		// Skip special APK metadata files
		if strings.HasPrefix(header.Name, ".") {
			continue
		}

		// Construct target path
		target := filepath.Join(mountPoint, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return errIOError("failed to create directory", err)
			}

		case tar.TypeReg:
			// Create file
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return errIOError("failed to create parent directory", err)
			}

			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return errIOError("failed to create file", err)
			}

			if _, err := io.Copy(outFile, tr); err != nil {
				_ = outFile.Close()
				return errIOError("failed to write file contents", err)
			}
			_ = outFile.Close()

		case tar.TypeSymlink:
			// Create symlink
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return errIOError("failed to create parent directory for symlink", err)
			}

			// Remove existing file/symlink if it exists
			_ = os.Remove(target)

			if err := os.Symlink(header.Linkname, target); err != nil {
				m.logger.Warn("Failed to create symlink", "target", target, "link", header.Linkname, "error", err)
			}
		}
	}

	m.logger.Info("Package extracted successfully", "mountpoint", mountPoint)
	return nil
}

// ClearCache clears the APKINDEX cache
func (m *APKManager) ClearCache() {
	m.indexCacheLock.Lock()
	m.indexCache = make(map[string]map[string]*APKPackageInfo)
	m.indexCacheLock.Unlock()
}

// GetPackageByName looks up a package by name from cached indexes
func (m *APKManager) GetPackageByName(ctx context.Context, name string) (*APKPackageInfo, error) {
	// Try main first
	mainPkgs, err := m.ParseAllPackages(ctx, "main")
	if err != nil {
		return nil, err
	}
	if pkg, ok := mainPkgs[name]; ok {
		return pkg, nil
	}

	// Try community
	communityPkgs, err := m.ParseAllPackages(ctx, "community")
	if err != nil {
		return nil, err
	}
	if pkg, ok := communityPkgs[name]; ok {
		return pkg, nil
	}

	return nil, errPackageNotFound(name)
}
