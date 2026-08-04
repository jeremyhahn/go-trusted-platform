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

package app

import (
	"context"
	"crypto"
	"errors"
	"testing"

	gotpm2 "github.com/google/go-tpm/tpm2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubTPM satisfies xkmssdk.TrustedPlatformModule via embedding.
// Only used as a non-nil value to pass nil-checks in tests.
type stubTPM struct {
	xkmssdk.TrustedPlatformModule
}

// mockTPM satisfies xkmssdk.TrustedPlatformModule via embedding and overrides
// the three methods exercised by tpmDecrypter and getIDevIDDecrypter.
type mockTPM struct {
	xkmssdk.TrustedPlatformModule
	idevidFn      func() (crypto.PublicKey, error)
	idevidAttrsFn func() (*xkmssdk.KeyAttributes, error)
	rsaDecryptFn  func(handle gotpm2.TPMHandle, name gotpm2.TPM2BName, blob []byte) ([]byte, error)
}

func (m *mockTPM) IDevID() (crypto.PublicKey, error) {
	if m.idevidFn != nil {
		return m.idevidFn()
	}
	return nil, errors.New("mock: IDevID not configured")
}

func (m *mockTPM) IDevIDAttributes() (*xkmssdk.KeyAttributes, error) {
	if m.idevidAttrsFn != nil {
		return m.idevidAttrsFn()
	}
	return nil, errors.New("mock: IDevIDAttributes not configured")
}

func (m *mockTPM) RSADecrypt(handle gotpm2.TPMHandle, name gotpm2.TPM2BName, blob []byte) ([]byte, error) {
	if m.rsaDecryptFn != nil {
		return m.rsaDecryptFn(handle, name, blob)
	}
	return nil, errors.New("mock: RSADecrypt not configured")
}

// TestEnvironment_String verifies the Environment type converts to string correctly.
func TestEnvironment_String(t *testing.T) {
	tests := []struct {
		name     string
		env      Environment
		expected string
	}{
		{"dev", EnvDev, "dev"},
		{"preprod", EnvPreProd, "preprod"},
		{"prod", EnvProd, "prod"},
		{"test", EnvTest, "test"},
		{"custom", Environment("staging"), "staging"},
		{"empty", Environment(""), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.env.String())
		})
	}
}

// TestParseEnvironment verifies environment string parsing for known and unknown values.
func TestParseEnvironment(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Environment
	}{
		{"dev", "dev", EnvDev},
		{"preprod", "preprod", EnvPreProd},
		{"prod", "prod", EnvProd},
		{"test", "test", EnvTest},
		{"custom_environment", "staging", Environment("staging")},
		{"empty_string", "", Environment("")},
		{"uppercase_not_matched", "DEV", Environment("DEV")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseEnvironment(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestNewApp verifies that NewApp creates a properly initialized App with shutdown channel.
func TestNewApp(t *testing.T) {
	app := NewApp()

	require.NotNil(t, app)
	require.NotNil(t, app.ShutdownChan)

	// Verify the shutdown channel is buffered with capacity 1
	select {
	case app.ShutdownChan <- true:
		// Buffered channel accepts without blocking
	default:
		t.Fatal("ShutdownChan should be buffered with capacity 1")
	}

	// Second send should not block (channel full, should go to default)
	select {
	case app.ShutdownChan <- true:
		t.Fatal("ShutdownChan should be full after first send")
	default:
		// Expected: channel is full
	}
}

// TestApp_FQDN verifies the FQDN is correctly composed from hostname and domain.
func TestApp_FQDN(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		domain   string
		expected string
	}{
		{"standard_fqdn", "node01", "example.com", "node01.example.com"},
		{"subdomain", "api", "internal.example.com", "api.internal.example.com"},
		{"empty_hostname", "", "example.com", ".example.com"},
		{"empty_domain", "node01", "", "node01."},
		{"both_empty", "", "", "."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &App{Hostname: tt.hostname, Domain: tt.domain}
			assert.Equal(t, tt.expected, app.FQDN())
		})
	}
}

// TestApp_WebService verifies looking up web services by name.
func TestApp_WebService(t *testing.T) {
	ws1 := &v1.Config{Name: "api"}
	ws2 := &v1.Config{Name: "admin"}
	app := &App{WebServices: []*v1.Config{ws1, ws2}}

	t.Run("found", func(t *testing.T) {
		result := app.WebService("api")
		require.NotNil(t, result)
		assert.Equal(t, "api", result.Name)
	})

	t.Run("found_second", func(t *testing.T) {
		result := app.WebService("admin")
		require.NotNil(t, result)
		assert.Equal(t, "admin", result.Name)
	})

	t.Run("not_found", func(t *testing.T) {
		assert.Nil(t, app.WebService("nonexistent"))
	})

	t.Run("empty_name", func(t *testing.T) {
		assert.Nil(t, app.WebService(""))
	})

	t.Run("empty_webservices", func(t *testing.T) {
		assert.Nil(t, (&App{}).WebService("api"))
	})
}

// TestApp_PrimaryWebService verifies the priority logic for finding the primary web service.
func TestApp_PrimaryWebService(t *testing.T) {
	t.Run("prefers_webservice_config", func(t *testing.T) {
		app := &App{
			WebServiceConfig: &v1.Config{Name: "primary"},
			WebServices:      []*v1.Config{{Name: "fallback"}},
		}
		result := app.PrimaryWebService()
		require.NotNil(t, result)
		assert.Equal(t, "primary", result.Name)
	})

	t.Run("falls_back_to_webservices_first", func(t *testing.T) {
		app := &App{WebServices: []*v1.Config{{Name: "first"}, {Name: "second"}}}
		result := app.PrimaryWebService()
		require.NotNil(t, result)
		assert.Equal(t, "first", result.Name)
	})

	t.Run("returns_nil_when_nothing_configured", func(t *testing.T) {
		assert.Nil(t, (&App{}).PrimaryWebService())
	})

	t.Run("returns_nil_when_webservices_empty", func(t *testing.T) {
		assert.Nil(t, (&App{WebServices: []*v1.Config{}}).PrimaryWebService())
	})
}

// TestApp_GetInstallerConfig verifies that installer config is correctly extracted from App.
func TestApp_GetInstallerConfig(t *testing.T) {
	t.Run("with_all_fields", func(t *testing.T) {
		diskCfg := &installer.DiskConfig{}
		osCfg := &installer.OSConfig{}
		netCfg := &installer.NetworkConfig{}
		ukiCfg := &installer.UKIConfig{}
		sbCfg := &installer.SecureBootConfig{}
		fido2Cfg := &installer.FIDO2Config{}

		app := &App{
			DiskConfig: diskCfg, OSConfig: osCfg, NetworkConfig: netCfg,
			UKIConfig: ukiCfg, SecureBootConfig: sbCfg,
			EnableTPMSealing: true, SealPCRs: []uint{0, 7, 9},
			EnableFIDO2Enrollment: true, FIDO2Config: fido2Cfg,
			DebugFlag: true, Environment: EnvProd,
		}

		cfg := app.GetInstallerConfig()
		require.NotNil(t, cfg)
		assert.Equal(t, diskCfg, cfg.Disk)
		assert.Equal(t, osCfg, cfg.OS)
		assert.Equal(t, netCfg, cfg.Network)
		assert.Equal(t, ukiCfg, cfg.UKI)
		assert.Equal(t, sbCfg, cfg.SecureBoot)
		assert.True(t, cfg.EnableTPMSealing)
		assert.Equal(t, []uint{0, 7, 9}, cfg.PCRs)
		assert.True(t, cfg.EnableFIDO2Enrollment)
		assert.Equal(t, fido2Cfg, cfg.FIDO2)
		assert.True(t, cfg.Debug)
		assert.Equal(t, "prod", cfg.Environment)
	})

	t.Run("with_nil_fields", func(t *testing.T) {
		cfg := (&App{}).GetInstallerConfig()
		require.NotNil(t, cfg)
		assert.Nil(t, cfg.Disk)
		assert.Nil(t, cfg.OS)
		assert.False(t, cfg.EnableTPMSealing)
	})
}

// TestApp_SetInstallerConfig verifies that App fields are correctly populated from installer config.
func TestApp_SetInstallerConfig(t *testing.T) {
	t.Run("full_config", func(t *testing.T) {
		cfg := &installer.Config{
			Disk: &installer.DiskConfig{}, OS: &installer.OSConfig{},
			Network: &installer.NetworkConfig{}, UKI: &installer.UKIConfig{},
			SecureBoot:       &installer.SecureBootConfig{},
			EnableTPMSealing: true, PCRs: []uint{0, 7},
			EnableFIDO2Enrollment: true, FIDO2: &installer.FIDO2Config{},
			Debug: true, Environment: "prod",
		}

		app := &App{}
		app.SetInstallerConfig(cfg)

		assert.Equal(t, cfg.Disk, app.DiskConfig)
		assert.Equal(t, cfg.OS, app.OSConfig)
		assert.True(t, app.EnableTPMSealing)
		assert.Equal(t, []uint{0, 7}, app.SealPCRs)
		assert.True(t, app.DebugFlag)
		assert.Equal(t, EnvProd, app.Environment)
	})

	t.Run("nil_config_does_nothing", func(t *testing.T) {
		app := &App{DebugFlag: true, Environment: EnvDev}
		app.SetInstallerConfig(nil)
		assert.True(t, app.DebugFlag)
		assert.Equal(t, EnvDev, app.Environment)
	})

	t.Run("debug_false_does_not_override", func(t *testing.T) {
		app := &App{DebugFlag: true}
		app.SetInstallerConfig(&installer.Config{Debug: false})
		assert.True(t, app.DebugFlag)
	})

	t.Run("empty_environment_does_not_override", func(t *testing.T) {
		app := &App{Environment: EnvProd}
		app.SetInstallerConfig(&installer.Config{Environment: ""})
		assert.Equal(t, EnvProd, app.Environment)
	})
}

// TestApp_GetSetInstallerConfig_RoundTrip verifies symmetry between Get and Set.
func TestApp_GetSetInstallerConfig_RoundTrip(t *testing.T) {
	original := &App{
		DiskConfig: &installer.DiskConfig{}, OSConfig: &installer.OSConfig{},
		NetworkConfig: &installer.NetworkConfig{}, EnableTPMSealing: true,
		SealPCRs: []uint{0, 7, 9}, EnableFIDO2Enrollment: true,
		FIDO2Config: &installer.FIDO2Config{}, DebugFlag: true, Environment: EnvProd,
	}

	cfg := original.GetInstallerConfig()
	restored := &App{}
	restored.SetInstallerConfig(cfg)

	assert.Equal(t, original.EnableTPMSealing, restored.EnableTPMSealing)
	assert.Equal(t, original.SealPCRs, restored.SealPCRs)
	assert.Equal(t, original.DebugFlag, restored.DebugFlag)
	assert.Equal(t, original.Environment, restored.Environment)
}

// TestApp_Close verifies graceful shutdown behavior.
func TestApp_Close(t *testing.T) {
	t.Run("close_with_nil_factory", func(t *testing.T) {
		assert.NoError(t, NewApp().Close(context.Background()))
	})

	t.Run("close_signals_shutdown_channel", func(t *testing.T) {
		app := NewApp()
		require.NoError(t, app.Close(context.Background()))

		select {
		case val := <-app.ShutdownChan:
			assert.True(t, val)
		default:
			t.Fatal("expected shutdown signal on channel")
		}
	})

	t.Run("close_with_nil_shutdown_channel", func(t *testing.T) {
		assert.NoError(t, (&App{}).Close(context.Background()))
	})

	t.Run("close_with_full_shutdown_channel", func(t *testing.T) {
		app := NewApp()
		app.ShutdownChan <- true
		assert.NoError(t, app.Close(context.Background()))
	})
}

// TestApp_DAOFactory verifies the DAOFactory accessor.
func TestApp_DAOFactory(t *testing.T) {
	assert.Nil(t, (&App{}).DAOFactory())
}

// TestApp_KMS_NilFactory verifies KMS returns nil when daoFactory is nil.
func TestApp_KMS_NilFactory(t *testing.T) {
	assert.Nil(t, (&App{Logger: logging.DefaultLogger()}).KMS())
}

// TestApp_QuicBaaSService_NilFactory verifies QuicBaaSService returns nil when daoFactory is nil.
func TestApp_QuicBaaSService_NilFactory(t *testing.T) {
	assert.Nil(t, (&App{}).QuicBaaSService())
}

// TestApp_QuicBaaSSDKClient_NilFactory verifies SDK client returns nil when daoFactory is nil.
func TestApp_QuicBaaSSDKClient_NilFactory(t *testing.T) {
	assert.Nil(t, (&App{}).QuicBaaSSDKClient())
}

// TestApp_Secrets_NilFactory verifies Secrets returns nil when QuicBaaS service is nil.
func TestApp_Secrets_NilFactory(t *testing.T) {
	assert.Nil(t, (&App{Logger: logging.DefaultLogger()}).Secrets())
}

// TestApp_SetupSecretResolvers verifies secret resolver setup scenarios.
func TestApp_SetupSecretResolvers(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("nil_config", func(t *testing.T) {
		_, err := (&App{Logger: logger}).SetupSecretResolvers(context.Background(), nil)
		require.Error(t, err)
		var nilErr ErrNilSecretsConfig
		assert.ErrorAs(t, err, &nilErr)
	})

	t.Run("autogen_only", func(t *testing.T) {
		registry, err := (&App{Logger: logger}).SetupSecretResolvers(context.Background(),
			&SecretsConfig{})
		require.NoError(t, err)
		require.NotNil(t, registry)
	})

	t.Run("local_kms_no_service", func(t *testing.T) {
		registry, err := (&App{Logger: logger}).SetupSecretResolvers(context.Background(),
			&SecretsConfig{LocalKMS: true})
		require.NoError(t, err)
		require.NotNil(t, registry)
	})

	t.Run("encrypted_no_tpm", func(t *testing.T) {
		registry, err := (&App{Logger: logger}).SetupSecretResolvers(context.Background(),
			&SecretsConfig{Encrypted: true})
		require.NoError(t, err)
		require.NotNil(t, registry)
	})

	t.Run("all_enabled", func(t *testing.T) {
		registry, err := (&App{Logger: logger}).SetupSecretResolvers(context.Background(),
			&SecretsConfig{LocalKMS: true, Encrypted: true})
		require.NoError(t, err)
		require.NotNil(t, registry)
	})

	t.Run("none_enabled", func(t *testing.T) {
		registry, err := (&App{Logger: logger}).SetupSecretResolvers(context.Background(),
			&SecretsConfig{})
		require.NoError(t, err)
		require.NotNil(t, registry)
	})
}

// TestApp_ProcessSecrets verifies secrets processing scenarios.
func TestApp_ProcessSecrets(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("nil_config", func(t *testing.T) {
		_, err := (&App{Logger: logger}).ProcessSecrets(context.Background(), nil)
		require.Error(t, err)
		var nilErr ErrNilSecretsConfig
		assert.ErrorAs(t, err, &nilErr)
	})

	t.Run("disabled", func(t *testing.T) {
		result, err := (&App{Logger: logger}).ProcessSecrets(context.Background(),
			&SecretsConfig{Enabled: false})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Zero(t, result.Resolved)
		assert.Empty(t, result.Unresolved)
		assert.Empty(t, result.Errors)
	})

	t.Run("enabled_no_kms_uris", func(t *testing.T) {
		// App with no config fields containing secret URIs: processor resolves 0 fields.
		result, err := (&App{Logger: logger}).ProcessSecrets(context.Background(),
			&SecretsConfig{Enabled: true})
		require.NoError(t, err)
		require.NotNil(t, result)
	})
}

// TestApp_getIDevIDDecrypter verifies IDevID decrypter creation scenarios.
func TestApp_getIDevIDDecrypter(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("no_tpm", func(t *testing.T) {
		_, err := (&App{Logger: logger}).getIDevIDDecrypter(context.Background())
		require.Error(t, err)
		var tpmErr ErrTPMNotAvailable
		assert.ErrorAs(t, err, &tpmErr)
	})

	t.Run("no_idevid_config", func(t *testing.T) {
		_, err := (&App{
			Logger:    logger,
			TPM:       &stubTPM{},
			TPMConfig: xkmssdk.TPMConfig{IDevID: nil},
		}).getIDevIDDecrypter(context.Background())
		require.Error(t, err)
		var idevidErr ErrIDevIDNotConfigured
		assert.ErrorAs(t, err, &idevidErr)
	})
}

// TestTPMDecrypter_Decrypt verifies decrypter error handling.
func TestTPMDecrypter_Decrypt(t *testing.T) {
	t.Run("nil_attrs", func(t *testing.T) {
		d := &tpmDecrypter{attrs: nil}
		_, err := d.Decrypt(nil, []byte("ciphertext"), nil)
		require.Error(t, err)
		var idevidErr ErrIDevIDNotConfigured
		assert.ErrorAs(t, err, &idevidErr)
	})

	t.Run("nil_tpm_attributes", func(t *testing.T) {
		d := &tpmDecrypter{attrs: &xkmssdk.KeyAttributes{TPMAttributes: nil}}
		_, err := d.Decrypt(nil, []byte("ciphertext"), nil)
		require.Error(t, err)
		var idevidErr ErrIDevIDNotConfigured
		assert.ErrorAs(t, err, &idevidErr)
	})
}

// TestDefaultCAConfig verifies the default CA config is properly initialized.
func TestDefaultCAConfig(t *testing.T) {
	cfg := defaultCAConfig()
	require.NotNil(t, cfg)
	require.NotEmpty(t, cfg.Identity)

	for i, identity := range cfg.Identity {
		if len(identity.Keys) == 0 || identity.Keys[0] == nil {
			continue
		}
		assert.NotEmpty(t, identity.Keys[0].KeyAlgorithm,
			"identity[%d] should have a primary key algorithm configured", i)
	}
}

// TestDefaultConfig verifies the package-level DefaultConfig is properly set.
func TestDefaultConfig(t *testing.T) {
	assert.NotNil(t, DefaultConfig.CAConfig)
	assert.NotNil(t, DefaultConfig.QuicBaaSConfig)
	assert.NotNil(t, DefaultConfig.Logger)
	assert.NotNil(t, DefaultConfig.Random)
	assert.NotNil(t, DefaultConfig.WebServiceConfig)
	assert.NotEmpty(t, DefaultConfig.WebServices)
	assert.Equal(t, "trusted-data", DefaultConfig.PlatformDir)
	assert.Equal(t, "/etc/trusted-platform", DefaultConfig.ConfigDir)
	assert.True(t, DefaultConfig.DebugFlag)
}

// TestTestConfig verifies the package-level TestConfig is properly set.
func TestTestConfig(t *testing.T) {
	assert.NotNil(t, TestConfig.CAConfig)
	assert.NotNil(t, TestConfig.QuicBaaSConfig)
	assert.NotNil(t, TestConfig.Logger)
	assert.NotNil(t, TestConfig.Random)
	assert.True(t, TestConfig.DebugFlag)
	assert.True(t, TestConfig.DebugSecretsFlag)
}

// TestApp_StartDNS_NilConfig verifies StartDNS is a no-op when DNS is not configured.
func TestApp_StartDNS_NilConfig(t *testing.T) {
	(&App{Logger: logging.DefaultLogger(), DNSConfig: nil}).StartDNS()
}

// TestApp_ParsePINs verifies PIN parsing in debug mode.
func TestApp_ParsePINs(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("custom_pins", func(t *testing.T) {
		app := &App{DebugFlag: true, DebugSecretsFlag: true, Logger: logger}
		soPIN, userPIN, err := app.ParsePINs([]byte("my-so-pin"), []byte("my-user-pin"))
		require.NoError(t, err)
		assert.Equal(t, []byte("my-so-pin"), soPIN.Bytes())
		assert.Equal(t, []byte("my-user-pin"), userPIN.Bytes())
	})

	t.Run("default_password_generates_random", func(t *testing.T) {
		app := &App{DebugFlag: true, DebugSecretsFlag: true, Logger: logger}
		soPIN, userPIN, err := app.ParsePINs(
			[]byte(xkmssdk.DEFAULT_PASSWORD), []byte(xkmssdk.DEFAULT_PASSWORD))
		require.NoError(t, err)
		assert.NotEqual(t, []byte(xkmssdk.DEFAULT_PASSWORD), soPIN.Bytes())
		assert.NotEqual(t, []byte(xkmssdk.DEFAULT_PASSWORD), userPIN.Bytes())
		assert.NotEmpty(t, soPIN.Bytes())
		assert.NotEmpty(t, userPIN.Bytes())
	})

	t.Run("nil_pins_in_debug_mode", func(t *testing.T) {
		app := &App{DebugFlag: true, Logger: logger}
		soPIN, userPIN, err := app.ParsePINs(nil, nil)
		require.NoError(t, err)
		assert.Empty(t, soPIN.Bytes())
		assert.Empty(t, userPIN.Bytes())
	})

	t.Run("mixed_default_and_custom", func(t *testing.T) {
		app := &App{DebugFlag: true, DebugSecretsFlag: true, Logger: logger}
		soPIN, userPIN, err := app.ParsePINs(
			[]byte(xkmssdk.DEFAULT_PASSWORD), []byte("custom-pin"))
		require.NoError(t, err)
		assert.NotEqual(t, []byte(xkmssdk.DEFAULT_PASSWORD), soPIN.Bytes())
		assert.Equal(t, []byte("custom-pin"), userPIN.Bytes())
	})

	t.Run("debug_secrets_false", func(t *testing.T) {
		app := &App{DebugFlag: true, DebugSecretsFlag: false, Logger: logger}
		soPIN, userPIN, err := app.ParsePINs(
			[]byte(xkmssdk.DEFAULT_PASSWORD), []byte(xkmssdk.DEFAULT_PASSWORD))
		require.NoError(t, err)
		assert.NotEqual(t, []byte(xkmssdk.DEFAULT_PASSWORD), soPIN.Bytes())
		assert.NotEqual(t, []byte(xkmssdk.DEFAULT_PASSWORD), userPIN.Bytes())
	})
}

// TestApp_ParsePINs_Uniqueness verifies generated PINs are unique.
func TestApp_ParsePINs_Uniqueness(t *testing.T) {
	app := &App{DebugFlag: true, Logger: logging.DefaultLogger()}
	defaultPW := []byte(xkmssdk.DEFAULT_PASSWORD)

	sopin1, _, err1 := app.ParsePINs(defaultPW, []byte("fixed"))
	sopin2, _, err2 := app.ParsePINs(defaultPW, []byte("fixed"))

	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.NotEqual(t, sopin1.Bytes(), sopin2.Bytes())
}

// TestApp_OpenTPM_NilEK verifies early return when EK is nil.
func TestApp_OpenTPM_NilEK(t *testing.T) {
	t.Run("no_initialize", func(t *testing.T) {
		err := (&App{
			Logger:      logging.DefaultLogger(),
			PlatformDir: t.TempDir(),
			TPM:         &stubTPM{},
			TPMConfig:   xkmssdk.TPMConfig{EK: nil},
		}).OpenTPM(false)
		require.Error(t, err)
		assert.Equal(t, xkmssdk.ErrTPMNotInitialized, err)
	})

	t.Run("with_initialize", func(t *testing.T) {
		err := (&App{
			Logger:      logging.DefaultLogger(),
			PlatformDir: t.TempDir(),
			TPM:         &stubTPM{},
			TPMConfig:   xkmssdk.TPMConfig{EK: nil},
		}).OpenTPM(true)
		require.Error(t, err)
		assert.Equal(t, xkmssdk.ErrTPMNotInitialized, err)
	})
}

// TestApp_InitACMEClient_EarlyReturns verifies ACME client initialization edge cases.
func TestApp_InitACMEClient_EarlyReturns(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("nil_config", func(t *testing.T) {
		assert.NoError(t, (&App{Logger: logger, ACMEConfig: nil}).InitACMEClient(t.Context(), false))
	})

	t.Run("nil_client", func(t *testing.T) {
		assert.NoError(t, (&App{
			Logger:     logger,
			ACMEConfig: &trustedca.ACMEConfig{Client: nil},
		}).InitACMEClient(t.Context(), false))
	})

	t.Run("nil_ca", func(t *testing.T) {
		err := (&App{
			Logger:     logger,
			ACMEConfig: &trustedca.ACMEConfig{Client: &trustedca.ACMEClientYAMLConfig{}},
			CA:         nil,
		}).InitACMEClient(t.Context(), false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CA not configured")
	})
}

// TestApp_NewACMECrossSigner_EarlyReturns verifies ACME cross-signer edge cases.
func TestApp_NewACMECrossSigner_EarlyReturns(t *testing.T) {
	t.Run("nil_acme_config", func(t *testing.T) {
		client, err := (&App{ACMEConfig: nil}).NewACMECrossSigner(nil, false)
		assert.NoError(t, err)
		assert.Nil(t, client)
	})

	t.Run("nil_acme_client", func(t *testing.T) {
		_, err := (&App{ACMEConfig: &trustedca.ACMEConfig{}, ACMEClient: nil}).NewACMECrossSigner(nil, false)
		require.Error(t, err)
		assert.ErrorIs(t, err, trustedca.ACMEErrInvalidConfiguration)
	})
}

// TestApp_NewCertificateStore_NilObjectStore verifies error with nil object store.
func TestApp_NewCertificateStore_NilObjectStore(t *testing.T) {
	_, err := (&App{Logger: logging.DefaultLogger(), ObjectStore: nil}).NewCertificateStore(nil)
	require.Error(t, err)
	var target ErrNilObjectStore
	assert.ErrorAs(t, err, &target)
}

// TestApp_DropPrivileges_NonRoot verifies DropPrivileges is safe for non-root.
func TestApp_DropPrivileges_NonRoot(t *testing.T) {
	app := &App{
		Logger:      logging.DefaultLogger(),
		RuntimeUser: "nobody",
	}
	// Should not panic or change anything when not running as root
	app.DropPrivileges()
}

// TestApp_SecureWipePasses verifies the field can be set and read.
func TestApp_SecureWipePasses(t *testing.T) {
	tests := []struct {
		name   string
		passes int
	}{
		{"single_pass", 1},
		{"dod_standard", 3},
		{"dod_extended", 7},
		{"zero", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &App{SecureWipePasses: tt.passes}
			assert.Equal(t, tt.passes, app.SecureWipePasses)
		})
	}
}

// =============================================================================
// getIDevIDDecrypter additional paths (using mockTPM)
// =============================================================================

// TestApp_getIDevIDDecrypter_IDevIDAttrsError verifies that an error from
// IDevIDAttributes() is surfaced as ErrGetIDevIDAttrs.
func TestApp_getIDevIDDecrypter_IDevIDAttrsError(t *testing.T) {
	attrsCause := errors.New("tpm: handle revoked")
	app := &App{
		Logger: logging.DefaultLogger(),
		TPM: &mockTPM{
			idevidAttrsFn: func() (*xkmssdk.KeyAttributes, error) {
				return nil, attrsCause
			},
		},
		TPMConfig: xkmssdk.TPMConfig{IDevID: &xkmssdk.IDevIDConfig{}},
	}

	_, err := app.getIDevIDDecrypter(context.Background())
	require.Error(t, err)
	var attrsErr ErrGetIDevIDAttrs
	require.ErrorAs(t, err, &attrsErr)
	assert.ErrorIs(t, attrsErr.Cause, attrsCause)
}

// TestApp_getIDevIDDecrypter_Success verifies that a successful
// IDevIDAttributes() call returns a non-nil tpmDecrypter.
func TestApp_getIDevIDDecrypter_Success(t *testing.T) {
	attrs := &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: gotpm2.TPMHandle(0x81000001),
			Name:   gotpm2.TPM2BName{Buffer: []byte("test-name")},
		},
	}
	app := &App{
		Logger: logging.DefaultLogger(),
		TPM: &mockTPM{
			idevidAttrsFn: func() (*xkmssdk.KeyAttributes, error) {
				return attrs, nil
			},
		},
		TPMConfig: xkmssdk.TPMConfig{IDevID: &xkmssdk.IDevIDConfig{}},
	}

	decrypter, err := app.getIDevIDDecrypter(context.Background())
	require.NoError(t, err)
	require.NotNil(t, decrypter)
}

// =============================================================================
// tpmDecrypter.Public() tests
// =============================================================================

// TestTPMDecrypter_Public_Success verifies Public() returns the key from IDevID.
func TestTPMDecrypter_Public_Success(t *testing.T) {
	// crypto.PublicKey is interface{}, any non-nil value works as a sentinel.
	// We use *xkmssdk.KeyAttributes as a convenient non-nil pointer type already
	// imported in this test file.
	sentinel := &xkmssdk.KeyAttributes{}

	mock := &mockTPM{
		idevidFn: func() (crypto.PublicKey, error) {
			return sentinel, nil
		},
	}
	d := &tpmDecrypter{tpm: mock, attrs: &xkmssdk.KeyAttributes{}}
	pub := d.Public()
	assert.Equal(t, sentinel, pub)
}

// TestTPMDecrypter_Public_Error verifies Public() returns nil when IDevID fails.
func TestTPMDecrypter_Public_Error(t *testing.T) {
	mock := &mockTPM{
		idevidFn: func() (crypto.PublicKey, error) {
			return nil, errors.New("tpm: IDevID key not provisioned")
		},
	}
	d := &tpmDecrypter{tpm: mock, attrs: &xkmssdk.KeyAttributes{}}
	assert.Nil(t, d.Public())
}

// =============================================================================
// tpmDecrypter.Decrypt() RSADecrypt paths
// =============================================================================

// TestTPMDecrypter_Decrypt_RSADecryptError verifies that an RSADecrypt failure
// propagates as-is.
func TestTPMDecrypter_Decrypt_RSADecryptError(t *testing.T) {
	cause := errors.New("tpm: authorization failed")
	mock := &mockTPM{
		rsaDecryptFn: func(handle gotpm2.TPMHandle, name gotpm2.TPM2BName, blob []byte) ([]byte, error) {
			return nil, cause
		},
	}
	attrs := &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: gotpm2.TPMHandle(0x81000001),
			Name:   gotpm2.TPM2BName{Buffer: []byte("test-name")},
		},
	}
	d := &tpmDecrypter{tpm: mock, attrs: attrs}

	_, err := d.Decrypt(nil, []byte("ciphertext"), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, cause)
}

// TestTPMDecrypter_Decrypt_RSADecryptSuccess verifies the happy path: the
// plaintext returned by RSADecrypt is forwarded to the caller.
func TestTPMDecrypter_Decrypt_RSADecryptSuccess(t *testing.T) {
	expected := []byte("decrypted-plaintext")
	mock := &mockTPM{
		rsaDecryptFn: func(handle gotpm2.TPMHandle, name gotpm2.TPM2BName, blob []byte) ([]byte, error) {
			assert.Equal(t, gotpm2.TPMHandle(0x81000001), handle)
			assert.Equal(t, []byte("test-name"), name.Buffer)
			assert.Equal(t, []byte("ciphertext"), blob)
			return expected, nil
		},
	}
	attrs := &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: gotpm2.TPMHandle(0x81000001),
			Name:   gotpm2.TPM2BName{Buffer: []byte("test-name")},
		},
	}
	d := &tpmDecrypter{tpm: mock, attrs: attrs}

	result, err := d.Decrypt(nil, []byte("ciphertext"), nil)
	require.NoError(t, err)
	assert.Equal(t, expected, result)
}

// =============================================================================
// SetupSecretResolvers with IDevID decrypter available
// =============================================================================

// TestSetupSecretResolvers_Encrypted_WithDecrypter verifies that when Encrypted=true
// and a working IDevID decrypter is available, the idevid:// resolver is registered.
func TestSetupSecretResolvers_Encrypted_WithDecrypter(t *testing.T) {
	attrs := &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: gotpm2.TPMHandle(0x81000001),
			Name:   gotpm2.TPM2BName{Buffer: []byte("test-name")},
		},
	}
	app := &App{
		Logger: logging.DefaultLogger(),
		TPM: &mockTPM{
			idevidAttrsFn: func() (*xkmssdk.KeyAttributes, error) {
				return attrs, nil
			},
		},
		TPMConfig: xkmssdk.TPMConfig{IDevID: &xkmssdk.IDevIDConfig{}},
	}

	registry, err := app.SetupSecretResolvers(context.Background(), &SecretsConfig{Encrypted: true})
	require.NoError(t, err)
	require.NotNil(t, registry)
	// The idevid:// resolver must be registered.
	assert.True(t, registry.IsSecretURI("idevid://some-ciphertext"))
}
