// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package backends

import (
	"crypto/fips140"

	luks2 "github.com/jeremyhahn/go-luks2/pkg/luks2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
)

// fipsAddKeyOptions builds AddKeyOptions with the platform's FIPS keyslot
// policy already applied.
//
// The daemon's LUKS API previously called luks2.AddKey with nil options on
// every enrolment path. go-luks2 documents an unset KDF as defaulting to
// argon2id and does not consult /proc/sys/crypto/fips_enabled itself, so those
// calls persisted non-approved keyslots on a FIPS-activated host — the public
// API being the surface most likely to be used, and the one where it mattered
// most.
//
// Outside FIPS this returns options that leave everything empty, so go-luks2's
// own defaults apply exactly as before.
func fipsAddKeyOptions() (*luks2.AddKeyOptions, error) {
	opts := &luks2.AddKeyOptions{}
	if err := resolveLUKSKeyslotPolicy(&opts.KDFType, &opts.Hash); err != nil {
		return nil, err
	}
	return opts, nil
}

// fipsRecoveryKeyPolicy applies the same keyslot policy to a recovery key.
//
// RecoveryKeyOptions carries a KDFType that go-luks2 also defaults to argon2id,
// and it has no hash field, so only the KDF is resolved. A recovery key is a
// keyslot like any other — it unlocks the volume — so leaving it outside the
// policy would have left a FIPS-activated system with one non-approved keyslot
// among approved ones, which is the same exposure with a smaller blast radius.
func fipsRecoveryKeyPolicy(kdfType *string) error {
	var noHash string
	return resolveLUKSKeyslotPolicy(kdfType, &noHash)
}

// luksFIPSActive reports whether a keyslot this backend writes must use an
// approved KDF: the kernel's FIPS indicator is set, or the Go cryptographic
// module runs in FIPS 140-3 mode (GODEBUG=fips140=on or only). The second
// holds on a host whose kernel is not in FIPS mode, and there the module
// refuses Argon2 outright, so a keyslot left to go-luks2's argon2id default
// fails to enroll at all.
func luksFIPSActive() bool {
	return fips.IsEnabled() || fips140.Enabled()
}

// resolveLUKSKeyslotPolicy applies fips.ResolveKeyslotPolicy, and in addition
// selects PBKDF2 for an unset KDF when the Go cryptographic module is in FIPS
// 140-3 mode. fips.IsEnabled reads only the kernel indicator, so without this a
// fips140=only process on a non-FIPS kernel left the KDF to go-luks2's argon2id
// default and every enrollment failed in CreateKDF. The hash is left to
// go-luks2's PBKDF2 default, SHA-256, which is approved.
func resolveLUKSKeyslotPolicy(kdfType, hash *string) error {
	if fips140.Enabled() && *kdfType == "" {
		*kdfType = fips.KDFPBKDF2
	}
	return fips.ResolveKeyslotPolicy(kdfType, hash)
}
