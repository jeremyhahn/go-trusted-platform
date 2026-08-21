// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package luks

import "github.com/jeremyhahn/go-trusted-platform/pkg/fips"

// applyFIPSKeyslotPolicy is the ADD-KEY path policy. go-luks2's AddKey uses the
// hash only as the PBKDF2 PRF and calls AFSplit with its own default, so the
// format path's digest constraint does not apply here.
func applyFIPSKeyslotPolicy(kdfType, hash *string) error {
	return fips.ResolveKeyslotPolicy(kdfType, hash)
}

// applyFIPSFormatPolicy is the FORMAT path policy. FormatOptions.HashAlgo is
// shared with the anti-forensic splitter, which constrains the usable digests
// and makes hash-qualified KDF aliases unreliable — see
// fips.ResolveFormatKeyslotPolicy.
func applyFIPSFormatPolicy(kdfType, hashAlgo *string) error {
	return fips.ResolveFormatKeyslotPolicy(kdfType, hashAlgo)
}
