// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build fips

package iso

import (
	"errors"
	"fmt"
	"hash"
)

// ErrFIPSAPKChecksumUnavailable reports that offline APK prefetch cannot run in
// a FIPS build.
//
// Unlike the other FIPS gates in this repository, there is no approved
// alternative to fall back to: the APKINDEX "Q1" field is DEFINED as
// base64(SHA-1), and apk rejects any other value, so the format cannot be
// satisfied without computing SHA-1. Prefetching an offline repository is
// therefore unavailable in a FIPS build; ISO builds that fetch packages from
// the network at install time are unaffected.
type ErrFIPSAPKChecksumUnavailable struct{}

func (ErrFIPSAPKChecksumUnavailable) Error() string {
	return fmt.Sprint(
		"iso: offline APK prefetch requires the APKINDEX Q1 checksum, which the format ",
		"defines as SHA-1; a FIPS build cannot compute it. Build the ISO without ",
		"prefetch, or use a non-FIPS build for image assembly.")
}

// newAPKChecksumHasher fails closed rather than emitting an index apk would
// reject.
func newAPKChecksumHasher() (hash.Hash, error) {
	return nil, ErrFIPSAPKChecksumUnavailable{}
}

// isFIPSChecksumRefusal reports whether an error is this build's refusal to
// compute the APKINDEX checksum, which must abort the whole index rather than
// skip a package: every package would fail identically, and the result would be
// an empty index reported as a success.
func isFIPSChecksumRefusal(err error) bool {
	var refusal ErrFIPSAPKChecksumUnavailable
	return errors.As(err, &refusal)
}
