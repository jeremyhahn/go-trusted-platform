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

//go:build integration

package bmc_integration

import (
	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// enrollOptionsToSDK converts the integration-test-local EnrollOptions to the
// SDK's bmcsvc.EnrollOptions. Both types have the same nullable-bool fields;
// the conversion is a straight field copy.
func enrollOptionsToSDK(opts *EnrollOptions) *bmcsvc.EnrollOptions {
	if opts == nil {
		return nil
	}
	return &bmcsvc.EnrollOptions{
		ReplaceCertificate: opts.ReplaceCertificate,
		RotatePassword:     opts.RotatePassword,
		DNSRegister:        opts.DNSRegister,
		DANEPublish:        opts.DANEPublish,
	}
}

// sdkEnrollResultToDomain converts the SDK's bmcsvc.EnrollResult to the
// integration-test-local EnrollResult. The SDK type is the authoritative domain
// object for gRPC and Unix adapters; the local type is used across all adapters
// for a uniform test assertion surface.
func sdkEnrollResultToDomain(r *bmcsvc.EnrollResult) *EnrollResult {
	if r == nil {
		return &EnrollResult{}
	}
	steps := make([]EnrollStep, len(r.Steps))
	for i, s := range r.Steps {
		steps[i] = EnrollStep{Name: s.Name, OK: s.OK, Detail: s.Detail}
	}
	return &EnrollResult{
		DeviceID:      r.DeviceID,
		Endpoint:      r.Endpoint,
		Hostname:      r.Hostname,
		DNSName:       r.DNSName,
		PinSPKISHA256: r.PinSPKISHA256,
		FactoryCertMeta: EnrollFactoryCertMeta{
			Subject:      r.FactoryCertMeta.Subject,
			Issuer:       r.FactoryCertMeta.Issuer,
			SerialNumber: r.FactoryCertMeta.SerialNumber,
			NotBefore:    r.FactoryCertMeta.NotBefore,
			NotAfter:     r.FactoryCertMeta.NotAfter,
			SPKISHA256:   r.FactoryCertMeta.SPKISHA256,
			SHA256:       r.FactoryCertMeta.SHA256,
			CapturedAt:   r.FactoryCertMeta.CapturedAt,
		},
		Steps: steps,
	}
}

// sdkRestoreResultToDomain converts the SDK's bmcsvc.RestoreResult to the
// integration-test-local RestoreResult. The SDK type is the authoritative domain
// object for gRPC and Unix adapters.
func sdkRestoreResultToDomain(r *bmcsvc.RestoreResult) *RestoreResult {
	if r == nil {
		return &RestoreResult{}
	}
	steps := make([]EnrollStep, len(r.Steps))
	for i, s := range r.Steps {
		steps[i] = EnrollStep{Name: s.Name, OK: s.OK, Detail: s.Detail}
	}
	return &RestoreResult{
		DeviceID: r.DeviceID,
		Endpoint: r.Endpoint,
		Hostname: r.Hostname,
		NewCertMeta: RestoreFactoryCertMeta{
			Subject:      r.NewCertMeta.Subject,
			Issuer:       r.NewCertMeta.Issuer,
			SerialNumber: r.NewCertMeta.SerialNumber,
			NotBefore:    r.NewCertMeta.NotBefore,
			NotAfter:     r.NewCertMeta.NotAfter,
			SPKISHA256:   r.NewCertMeta.SPKISHA256,
			SHA256:       r.NewCertMeta.SHA256,
			CapturedAt:   r.NewCertMeta.CapturedAt,
		},
		Steps: steps,
	}
}
