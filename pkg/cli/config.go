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

package cli

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the platformctl configuration (similar to kubeconfig)
type Config struct {
	CurrentContext string     `yaml:"current_context" json:"current_context"`
	Contexts       []*Context `yaml:"contexts" json:"contexts"`

	// path is the file LoadConfig read, so Save("") writes back to the
	// same --config / PLATFORMCTL_CONFIG file instead of the default.
	path string
}

// SystemConfigPath is the system-wide config file path, used as the fallback
// when the calling user has no resolvable home directory (daemon and service
// contexts). It is a fixed absolute path, not composed per platform.
const SystemConfigPath = "/etc/platformctl/config.yaml"

// DefaultConfigPath returns the default config file path
func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return SystemConfigPath
	}
	return filepath.Join(home, ".platformctl", "config.yaml")
}

// LoadConfig loads the configuration from the specified path
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return default config if file doesn't exist
			config := DefaultConfig()
			config.path = path
			return config, nil
		}
		return nil, ErrConfigReadFailed{Path: path, Err: err}
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, ErrConfigParseFailed{Path: path, Err: err}
	}

	// Apply defaults when parsed config is missing required fields
	if len(config.Contexts) == 0 || config.CurrentContext == "" {
		defaults := DefaultConfig()
		if len(config.Contexts) == 0 {
			config.Contexts = defaults.Contexts
		}
		if config.CurrentContext == "" {
			config.CurrentContext = defaults.CurrentContext
		}
	}

	config.path = path
	return &config, nil
}

// Save saves the configuration to the specified path. An empty path means
// the file the configuration was loaded from, else the default path.
func (c *Config) Save(path string) error {
	if path == "" {
		path = c.path
	}
	if path == "" {
		path = DefaultConfigPath()
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return ErrConfigDirCreateFailed{Path: dir, Err: err}
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return ErrConfigMarshalFailed{Err: err}
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return ErrConfigWriteFailed{Path: path, Err: err}
	}

	return nil
}

// GetCurrentContext returns the currently active context
func (c *Config) GetCurrentContext() (*Context, error) {
	if c.CurrentContext == "" {
		return nil, ErrNoContextSet{}
	}

	for _, ctx := range c.Contexts {
		if ctx.Name == c.CurrentContext {
			return ctx, nil
		}
	}

	return nil, ErrContextNotFound{Context: c.CurrentContext}
}

// GetContext returns a context by name
func (c *Config) GetContext(name string) (*Context, error) {
	for _, ctx := range c.Contexts {
		if ctx.Name == name {
			return ctx, nil
		}
	}
	return nil, ErrContextNotFound{Context: name}
}

// AddContext adds or updates a context
func (c *Config) AddContext(ctx *Context) {
	for i, existing := range c.Contexts {
		if existing.Name == ctx.Name {
			c.Contexts[i] = ctx
			return
		}
	}
	c.Contexts = append(c.Contexts, ctx)
}

// RemoveContext removes a context by name
func (c *Config) RemoveContext(name string) error {
	for i, ctx := range c.Contexts {
		if ctx.Name == name {
			c.Contexts = append(c.Contexts[:i], c.Contexts[i+1:]...)
			if c.CurrentContext == name {
				c.CurrentContext = ""
			}
			return nil
		}
	}
	return ErrContextNotFound{Context: name}
}

// SetCurrentContext sets the current context
func (c *Config) SetCurrentContext(name string) error {
	for _, ctx := range c.Contexts {
		if ctx.Name == name {
			c.CurrentContext = name
			return nil
		}
	}
	return ErrContextNotFound{Context: name}
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		CurrentContext: "local",
		Contexts: []*Context{
			{
				Name: "local",
				Type: ContextTypeLocal,
				Local: &LocalContext{
					SocketPath: "/run/platformd.sock",
				},
			},
		},
	}
}

// AutoDetectContext automatically detects the appropriate context based on environment
func AutoDetectContext() (*Context, error) {
	// Check if running as root
	if os.Geteuid() == 0 {
		// Use local Unix socket
		socketPath := "/run/platformd.sock"
		if _, err := os.Stat(socketPath); err == nil {
			return &Context{
				Name: "local",
				Type: ContextTypeLocal,
				Local: &LocalContext{
					SocketPath: socketPath,
				},
			}, nil
		}
	}

	// Check for remote configuration in environment
	if server := os.Getenv("PLATFORMCTL_SERVER"); server != "" {
		ctx := &Context{
			Name: "remote-auto",
			Type: ContextTypeRemote,
			Remote: &RemoteContext{
				Server: server,
			},
		}

		if caCert := os.Getenv("PLATFORMCTL_CA_CERT"); caCert != "" {
			ctx.Remote.CACert = caCert
		}
		if clientCert := os.Getenv("PLATFORMCTL_CLIENT_CERT"); clientCert != "" {
			ctx.Remote.ClientCert = clientCert
		}
		if clientKey := os.Getenv("PLATFORMCTL_CLIENT_KEY"); clientKey != "" {
			ctx.Remote.ClientKey = clientKey
		}

		return ctx, nil
	}

	return nil, ErrAutoDetectionFailed{
		Reason: "not running as root and no remote server configured",
	}
}
