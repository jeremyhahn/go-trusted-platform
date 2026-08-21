// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package backends

import (
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
	if err := fips.ResolveKeyslotPolicy(&opts.KDFType, &opts.Hash); err != nil {
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
	return fips.ResolveKeyslotPolicy(kdfType, &noHash)
}
