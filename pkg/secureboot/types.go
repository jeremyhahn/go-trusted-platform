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

package secureboot

import "errors"

// KeyType represents the type of Secure Boot key
type KeyType string

const (
	// KeyTypePK is the Platform Key - the root of trust
	KeyTypePK KeyType = "PK"
	// KeyTypeKEK is the Key Exchange Key - used to sign DB updates
	KeyTypeKEK KeyType = "KEK"
	// KeyTypeDB is the Signature Database key - used to sign bootloaders
	KeyTypeDB KeyType = "DB"
)

// KeyPaths holds the file paths to Secure Boot certificates and keys.
// Private keys are also exported when ExportKeys is true in XKMSConfig,
// which is required for the installer to sign UKIs during system installation.
type KeyPaths struct {
	PKCert  string
	KEKCert string
	DBCert  string
	PKKey   string
	KEKKey  string
	DBKey   string
}

var (
	// ErrConfigNil indicates a nil configuration was provided
	ErrConfigNil = errors.New("config cannot be nil")
	// ErrInvalidConfig indicates the key configuration is invalid
	ErrInvalidConfig = errors.New("invalid key configuration")
	// ErrKeyGenFailed indicates key generation failed
	ErrKeyGenFailed = errors.New("key generation failed")
	// ErrKeysNotFound indicates required keys were not found
	ErrKeysNotFound = errors.New("keys not found")
	// ErrInvalidKeyType indicates an invalid key type was specified
	ErrInvalidKeyType = errors.New("invalid key type")
	// ErrWriteFailed indicates a file write operation failed
	ErrWriteFailed = errors.New("write operation failed")
)
