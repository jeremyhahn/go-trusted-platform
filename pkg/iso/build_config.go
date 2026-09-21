package iso

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
)

// NewPlatformISOConfig translates the CLI-level build configuration into the
// Customizer's configuration rooted at workDir. It is the one place the two
// shapes meet, shared by `platformctl iso create` and the disk image builder.
func NewPlatformISOConfig(build *ISOBuildConfig, workDir string) *PlatformISOConfig {
	cfg := &PlatformISOConfig{
		Alpine: AlpineConfig{
			Version:      build.AlpineVersion,
			Mirror:       build.AlpineMirror,
			APKMirror:    build.APKMirror,
			Architecture: build.Architecture,
		},
		Directories: DirectoryConfig{
			Work:    workDir,
			ISO:     filepath.Join(workDir, "iso"),
			Overlay: filepath.Join(workDir, "overlay"),
			Keys:    build.KeysDir,
		},
		Platform: PlatformConfig{
			Version:           build.PlatformVersion,
			PlatformdBinary:   build.PlatformdBinary,
			ConfigFile:        build.PlatformConfigFile,
			CABundlePath:      build.CABundlePath,
			CAKeyAlgorithm:    build.CAKeyAlgorithm,
			WebUIPath:         build.WebUIPath,
			PlatformType:      build.PlatformType,
			ConfigServerURL:   build.ConfigServerURL,
			BootstrapStrategy: build.BootstrapStrategy,
			BootstrapDNS:      build.BootstrapDNS,
			BootstrapNoiseKey: build.BootstrapNoiseKey,
			BootstrapSPKIPin:  build.BootstrapSPKIPin,
		},
		Security: SecurityConfig{
			SecureBoot: build.SecureBoot,
			TPM: TPMConfig{
				AutoUnseal:      build.TPMAutoUnseal,
				AutoUpgradeSeal: build.TPMAutoUpgradeSeal,
			},
			FIPS:        build.FIPS,
			Lockdown:    build.Lockdown,
			EnableFIDO2: build.EnableFIDO2,
		},
		LUKS: LUKSConfig{
			Enabled: build.LUKSTPMOnly,
			TPMOnly: build.LUKSTPMOnly,
		},
		RootFS: RootFSConfig{
			Type: build.RootFS,
		},
		Build: BuildOptions{
			Debug:    build.Debug,
			PreFetch: build.PreFetch,
		},
		Output: OutputConfig{
			Label: build.OutputLabel,
		},
	}
	cfg.SetDefaults()
	return cfg
}

// SecureBootKeysDecision says what EnsureSecureBootKeys did.
type SecureBootKeysDecision string

const (
	// SecureBootKeysDisabled: Secure Boot is off for this build.
	SecureBootKeysDisabled SecureBootKeysDecision = "disabled"
	// SecureBootKeysRemote: the platform config names a remote/KMS DB
	// signer, so no local key material is generated.
	SecureBootKeysRemote SecureBootKeysDecision = "remote"
	// SecureBootKeysExisting: keys were already present in the keys directory.
	SecureBootKeysExisting SecureBootKeysDecision = "existing"
	// SecureBootKeysGenerated: a fresh PK/KEK/DB set was generated.
	SecureBootKeysGenerated SecureBootKeysDecision = "generated"
	// SecureBootKeysNotRequested: key generation was turned off; whatever
	// the keys directory holds is used as-is.
	SecureBootKeysNotRequested SecureBootKeysDecision = "not-requested"
)

// EnsureSecureBootKeys generates the Secure Boot key set for a build when
// Secure Boot is on, generation is requested and the platform config does not
// delegate DB signing to a remote signer. It records the resolved keys
// directory in build.KeysDir.
func EnsureSecureBootKeys(ctx context.Context, logger *logging.Logger, build *ISOBuildConfig) (SecureBootKeysDecision, error) {
	if !build.SecureBoot {
		return SecureBootKeysDisabled, nil
	}
	if !build.GenerateKeys {
		return SecureBootKeysNotRequested, nil
	}
	if build.PlatformConfigFile != "" {
		remote, err := SecureBootRemoteSigning(build.PlatformConfigFile)
		if err != nil {
			return "", err
		}
		if remote {
			return SecureBootKeysRemote, nil
		}
	}

	keysDir := build.KeysDir
	if keysDir == "" {
		keysDir = filepath.Join(build.WorkDir, "secure-boot-keys")
	}
	backend := secureboot.BackendType(build.KeyBackend)
	if build.KeyBackend == "" {
		backend = secureboot.BackendFile
	}
	km, err := secureboot.NewXKMSManager(&secureboot.XKMSConfig{
		KeysDir:      keysDir,
		Backend:      backend,
		CommonName:   "Trusted Platform",
		Country:      "US",
		Organization: "Trusted Platform",
		KeySize:      2048,
		ValidYears:   10,
		ExportKeys:   true, // Always export for Secure Boot enrollment
	}, logger)
	if err != nil {
		return "", &WrappedError{Msg: "failed to create key manager", Err: err}
	}
	defer km.Close()

	build.KeysDir = keysDir
	if km.KeysExist() {
		return SecureBootKeysExisting, nil
	}
	if err := km.GenerateAll(ctx); err != nil {
		return "", &WrappedError{Msg: "failed to generate keys", Err: err}
	}
	return SecureBootKeysGenerated, nil
}

// VersionFileName is the repository file that carries the platform release.
const VersionFileName = "VERSION"

// ReadVersionFile returns the platform release from the VERSION file in the
// current directory, or "dev" when there is none.
func ReadVersionFile() string {
	data, err := os.ReadFile(VersionFileName)
	if err != nil {
		return "dev"
	}
	if v := strings.TrimSpace(string(data)); v != "" {
		return v
	}
	return "dev"
}
