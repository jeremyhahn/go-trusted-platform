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

package container

import (
	"context"
	"embed"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed policies/*.rego
var builtinPolicies embed.FS

// PolicyBundle contains compiled policies from all sources.
type PolicyBundle struct {
	// Policies maps policy names to their Rego source code.
	Policies map[string]string

	// LoadedAt is when the bundle was loaded.
	LoadedAt time.Time

	// Sources tracks where policies came from.
	Sources []PolicySource

	mu sync.RWMutex
}

// PolicySource describes where a policy was loaded from.
type PolicySource struct {
	// Type is the source type (builtin, directory, bundle).
	Type PolicySourceType

	// Location is the source location (path or URL).
	Location string

	// PolicyCount is the number of policies loaded from this source.
	PolicyCount int
}

// PolicySourceType identifies the type of policy source.
type PolicySourceType string

const (
	// PolicySourceBuiltin identifies embedded builtin policies.
	PolicySourceBuiltin PolicySourceType = "builtin"

	// PolicySourceDirectory identifies policies loaded from a directory.
	PolicySourceDirectory PolicySourceType = "directory"

	// PolicySourceBundle identifies policies loaded from a remote bundle.
	PolicySourceBundle PolicySourceType = "bundle"
)

// NewPolicyBundle creates a new empty PolicyBundle.
func NewPolicyBundle() *PolicyBundle {
	return &PolicyBundle{
		Policies: make(map[string]string),
		LoadedAt: time.Now(),
		Sources:  make([]PolicySource, 0),
	}
}

// AddPolicy adds a policy to the bundle.
func (b *PolicyBundle) AddPolicy(name, content string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Policies[name] = content
}

// GetPolicy returns a policy by name.
func (b *PolicyBundle) GetPolicy(name string) (string, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	content, ok := b.Policies[name]
	return content, ok
}

// GetAllPolicies returns all policies in the bundle.
func (b *PolicyBundle) GetAllPolicies() map[string]string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make(map[string]string, len(b.Policies))
	for k, v := range b.Policies {
		result[k] = v
	}
	return result
}

// PolicyCount returns the total number of policies.
func (b *PolicyBundle) PolicyCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.Policies)
}

// AddSource adds a source tracking entry.
func (b *PolicyBundle) AddSource(source PolicySource) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Sources = append(b.Sources, source)
}

// PolicyLoader loads policies from multiple sources.
type PolicyLoader struct {
	config PolicyConfig
	client *http.Client
}

// NewPolicyLoader creates a new PolicyLoader with the given configuration.
func NewPolicyLoader(config PolicyConfig) *PolicyLoader {
	return &PolicyLoader{
		config: config,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// LoadPolicies loads all policies from configured sources.
// Policies are loaded in order: builtin, custom directory, remote bundle.
// Later policies with the same name override earlier ones.
func (l *PolicyLoader) LoadPolicies(ctx context.Context) (*PolicyBundle, error) {
	bundle := NewPolicyBundle()

	// Load builtin policies first
	if l.config.EnableBuiltinPolicies {
		if err := l.loadBuiltinPolicies(bundle); err != nil {
			return nil, err
		}
	}

	// Load custom policies from directory
	if l.config.CustomPolicyDir != "" {
		if err := l.loadFromDirectory(ctx, l.config.CustomPolicyDir, bundle); err != nil {
			return nil, err
		}
	}

	// Load remote bundle
	if l.config.PolicyBundleURL != "" {
		if err := l.loadFromBundle(ctx, l.config.PolicyBundleURL, bundle); err != nil {
			return nil, err
		}
	}

	return bundle, nil
}

// loadBuiltinPolicies loads the embedded builtin policies.
func (l *PolicyLoader) loadBuiltinPolicies(bundle *PolicyBundle) error {
	count := 0

	err := fs.WalkDir(builtinPolicies, "policies", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".rego") {
			return nil
		}

		content, err := builtinPolicies.ReadFile(path)
		if err != nil {
			return err
		}

		// Use the file name without .rego as the policy name
		name := strings.TrimSuffix(filepath.Base(path), ".rego")
		bundle.AddPolicy("builtin/"+name, string(content))
		count++

		return nil
	})

	if err != nil {
		return err
	}

	bundle.AddSource(PolicySource{
		Type:        PolicySourceBuiltin,
		Location:    "embedded",
		PolicyCount: count,
	})

	return nil
}

// loadFromDirectory loads all .rego files from a directory.
func (l *PolicyLoader) loadFromDirectory(ctx context.Context, dir string, bundle *PolicyBundle) error {
	// Check if directory exists
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// Directory doesn't exist - not an error, just skip
			return nil
		}
		return err
	}

	if !info.IsDir() {
		return ErrInvalidPolicyFile
	}

	count := 0

	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".rego") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Use relative path as policy name
		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			relPath = filepath.Base(path)
		}
		name := strings.TrimSuffix(relPath, ".rego")
		bundle.AddPolicy("custom/"+name, string(content))
		count++

		return nil
	})

	if err != nil {
		return err
	}

	bundle.AddSource(PolicySource{
		Type:        PolicySourceDirectory,
		Location:    dir,
		PolicyCount: count,
	})

	return nil
}

// loadFromBundle fetches and loads a remote OPA bundle.
func (l *PolicyLoader) loadFromBundle(ctx context.Context, url string, bundle *PolicyBundle) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := l.client.Do(req)
	if err != nil {
		return ErrPolicyBundleFetchFailed
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ErrPolicyBundleFetchFailed
	}

	// Read response body with size limit
	const maxBundleSize = 10 * 1024 * 1024 // 10MB limit
	limitedReader := io.LimitReader(resp.Body, maxBundleSize)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return err
	}

	// Parse bundle content
	// OPA bundles can be tar.gz files or individual .rego files
	// For simplicity, we support raw .rego content here
	if strings.HasSuffix(url, ".rego") {
		name := strings.TrimSuffix(filepath.Base(url), ".rego")
		bundle.AddPolicy("bundle/"+name, string(data))
		bundle.AddSource(PolicySource{
			Type:        PolicySourceBundle,
			Location:    url,
			PolicyCount: 1,
		})
		return nil
	}

	// For tar.gz bundles, we would need to extract and parse
	// This is a simplified implementation that treats the content as raw rego
	bundle.AddPolicy("bundle/remote", string(data))
	bundle.AddSource(PolicySource{
		Type:        PolicySourceBundle,
		Location:    url,
		PolicyCount: 1,
	})

	return nil
}

// ReloadPolicies reloads all policies from configured sources.
func (l *PolicyLoader) ReloadPolicies(ctx context.Context) (*PolicyBundle, error) {
	return l.LoadPolicies(ctx)
}

// GetConfig returns the loader configuration.
func (l *PolicyLoader) GetConfig() PolicyConfig {
	return l.config
}
