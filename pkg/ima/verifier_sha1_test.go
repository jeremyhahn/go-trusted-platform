// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !fips

package ima

import "testing"

// TestVerifier_getHasher_SHA1 pins the default build's behaviour: a SHA-1 IMA
// measurement is verifiable, because systems whose policy selects the SHA-1
// PCR bank still produce them.
func TestVerifier_getHasher_SHA1(t *testing.T) {
	h, err := NewVerifier().getHasher("sha1")
	if err != nil {
		t.Fatalf("sha1 hasher unavailable in a non-FIPS build: %v", err)
	}
	if got := h.Size(); got != sha1DigestSize {
		t.Errorf("digest size = %d, want %d", got, sha1DigestSize)
	}
}

// TestVerifyEventLog_LegacySHA1TemplateHash keeps the legacy wire shape covered
// in the build that supports it: an `ima-ng` record whose template hash is
// SHA-1-width (20 bytes) while the file-data label says sha256. That is a real
// shape produced by systems using the SHA-1 PCR bank, and the default build
// must still verify it — only a FIPS build refuses.
func TestVerifyEventLog_LegacySHA1TemplateHash(t *testing.T) {
	result := NewVerifier().VerifyEventLog(&EventLog{
		TotalCount: 1,
		Events: []*Event{{
			PCR:           10,
			TemplateHash:  make([]byte, sha1DigestSize),
			TemplateName:  "ima-ng",
			FileHash:      make([]byte, 32),
			HashAlgorithm: "sha256",
			FilePath:      "/bin/bash",
		}},
	})
	if result == nil {
		t.Fatal("VerifyEventLog returned nil")
	}
	if !result.Passed {
		t.Errorf("the default build must still verify a legacy SHA-1-width template hash: %+v", result)
	}
}
