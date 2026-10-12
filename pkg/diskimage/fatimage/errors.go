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

package fatimage

import "strconv"

// NameError is a file or directory name FAT cannot hold, or two names that
// are the same name to FAT.
type NameError struct {
	Path   string
	Reason string
}

func (e *NameError) Error() string { return "fatimage: " + e.Path + ": " + e.Reason }

// ReadError is a source file or directory that could not be read.
type ReadError struct {
	Path string
	Err  error
}

func (e *ReadError) Error() string { return "fatimage: reading " + e.Path + ": " + e.Err.Error() }
func (e *ReadError) Unwrap() error { return e.Err }

// NotRegularError is a source entry that is neither a file nor a directory
// (a symlink, a device): a boot image holds only files and directories.
type NotRegularError struct {
	Path string
	Mode string
}

func (e *NotRegularError) Error() string {
	return "fatimage: " + e.Path + " is a " + e.Mode + ", not a file or a directory"
}

// TooLargeError is a tree that does not fit a FAT16 volume.
type TooLargeError struct {
	Clusters    int
	RootEntries int
}

func (e *TooLargeError) Error() string {
	if e.RootEntries > 0 {
		return "fatimage: the root directory needs " + strconv.Itoa(e.RootEntries) + " entries, more than FAT16 holds"
	}
	return "fatimage: the tree needs " + strconv.Itoa(e.Clusters) + " clusters at the largest cluster size, more than FAT16 holds"
}

// FormatError is an image that is not a FAT16 volume this package can read.
type FormatError struct {
	Reason string
}

// GeometryError is inconsistent FAT16 geometry that would make the reader seek
// outside the image or FAT.
type GeometryError struct {
	Field  string
	Reason string
}

func (e *GeometryError) Error() string {
	return "fatimage: invalid " + e.Field + " geometry: " + e.Reason
}

func (e *FormatError) Error() string { return "fatimage: " + e.Reason }

// NotFoundError is a path the image does not contain.
type NotFoundError struct {
	Path string
}

func (e *NotFoundError) Error() string { return "fatimage: " + e.Path + " is not in the image" }
