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

package drive

import (
	"errors"
	"strconv"
)

var (
	// ErrNoDrivesConfigured is returned when no drives are configured
	ErrNoDrivesConfigured = errors.New("no drives configured")

	// ErrNoSystemDrive is returned when no system drive is configured
	ErrNoSystemDrive = errors.New("no system drive configured")

	// ErrDriveIDRequired is returned when drive ID is missing
	ErrDriveIDRequired = errors.New("drive ID is required")

	// ErrDevicePathRequired is returned when device path is missing
	ErrDevicePathRequired = errors.New("device path is required")

	// ErrNoPartitions is returned when a drive has no partitions
	ErrNoPartitions = errors.New("drive must have at least one partition")

	// ErrPartitionIDRequired is returned when partition ID is missing
	ErrPartitionIDRequired = errors.New("partition ID is required")

	// ErrInvalidPartitionNumber is returned when partition number is invalid
	ErrInvalidPartitionNumber = errors.New("partition number must be >= 1")

	// ErrPartitionSizeRequired is returned when partition size is missing
	ErrPartitionSizeRequired = errors.New("partition size is required")

	// ErrRootNotEncrypted is returned when root partition is not encrypted but required
	ErrRootNotEncrypted = errors.New("root partition must be encrypted")

	// ErrCircularDependency is returned when mount dependencies form a cycle
	ErrCircularDependency = errors.New("circular dependency detected in mount order")

	// ErrDuplicatePartitionID is returned when partition IDs are not unique
	ErrDuplicatePartitionID = errors.New("duplicate partition ID")

	// ErrDuplicateDriveID is returned when drive IDs are not unique
	ErrDuplicateDriveID = errors.New("duplicate drive ID")

	// ErrInvalidFilesystemType is returned for unsupported filesystem types
	ErrInvalidFilesystemType = errors.New("invalid filesystem type")

	// ErrZFSPoolNameRequired is returned when ZFS options lack pool name
	ErrZFSPoolNameRequired = errors.New("ZFS pool name is required")

	// ErrEncryptionMappingNameRequired is returned when encryption lacks mapping name
	ErrEncryptionMappingNameRequired = errors.New("encryption mapping name is required")
)

// InvalidMappingNameError is returned when an encrypted partition's
// mapping-name is one go-luks2 refuses to unlock under. The partition is
// formatted before it is unlocked, so the name must be refused at validation,
// before the drive is wiped.
type InvalidMappingNameError struct {
	PartitionID string
	Name        string
	Err         error
}

func (e *InvalidMappingNameError) Error() string {
	return "partition " + e.PartitionID + ": invalid encryption mapping-name " + strconv.Quote(e.Name) + ": " + e.Err.Error()
}

func (e *InvalidMappingNameError) Unwrap() error {
	return e.Err
}
