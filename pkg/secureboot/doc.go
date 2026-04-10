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

// Package secureboot provides functionality for generating and managing UEFI Secure Boot keys.
//
// This package implements key generation for the three levels of Secure Boot keys:
//   - Platform Key (PK): The root of trust, used to sign KEK updates
//   - Key Exchange Key (KEK): Used to sign DB updates
//   - Signature Database (DB): Used to verify bootloader signatures
//
// The XKMSManager integrates with go-xkms to support multiple key storage backends:
//   - PKCS#8 (software keys stored as files)
//   - PKCS#11 (hardware security modules)
//   - TPM 2.0 (trusted platform modules)
//   - YubiKey (hardware security keys)
//   - AWS KMS, Azure Key Vault, GCP KMS (cloud key management)
//   - HashiCorp Vault (secrets management)
//
// Basic Usage:
//
//	import (
//	    "context"
//	    "github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
//	    "github.com/jeremyhahn/go-trusted-platform/pkg/logging"
//	)
//
//	func main() {
//	    config := &secureboot.XKMSConfig{
//	        KeysDir:      "/path/to/keys",
//	        Backend:      secureboot.BackendSoftware,
//	        CommonName:   "My Secure Boot",
//	        Country:      "US",
//	        Organization: "My Organization",
//	        KeySize:      2048,
//	        ValidYears:   10,
//	        ExportKeys:   true,
//	    }
//
//	    logger := logging.DefaultLogger()
//	    km, err := secureboot.NewXKMSManager(config, logger)
//	    if err != nil {
//	        panic(err)
//	    }
//
//	    // Generate all keys (idempotent)
//	    ctx := context.Background()
//	    if err := km.GenerateAll(ctx); err != nil {
//	        panic(err)
//	    }
//
//	    // Get key paths for enrollment
//	    paths := km.GetKeyPaths()
//	    println("PK Certificate:", paths.PKCert)
//	}
//
// Key Generation:
//
// Keys are generated with the following characteristics:
//   - RSA private keys with configurable size (minimum 2048 bits)
//   - Self-signed X.509 certificates with configurable validity period
//   - Keys stored in the configured backend (PKCS#8, HSM, TPM, etc.)
//   - Certificates exported for Secure Boot enrollment when ExportKeys is true
//   - Certificates marked as CA certificates with code signing capability
//
// Security Considerations:
//
// The generated keys form the root of trust for Secure Boot and should be:
//   - Generated on a secure system
//   - Stored in hardware security modules when possible (TPM, HSM, YubiKey)
//   - Backed up securely
//   - Protected with appropriate access controls
//   - Never shared publicly
//
// Idempotency:
//
// The GenerateAll method is idempotent. If keys already exist in the configured
// backend, generation is skipped. This allows safe repeated calls without
// overwriting existing keys.
package secureboot
