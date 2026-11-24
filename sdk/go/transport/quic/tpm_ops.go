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

package quic

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// Codecs for the physical-TPM event log, random and credential calls
// (OpTPM2Category · 0x13 / 0x14 / 0x20 / 0x21). The bodies are the shared
// quicwire types the server handler answers (#2069).

var tpmOpsRequestEncoders = map[string]categoryRequestEncoder{
	platformv1.TPMService_GetRandom_FullMethodName: requestEncoder(platformv1.TPMService_GetRandom_FullMethodName,
		func(r *platformv1.GetRandomRequest) (interface{}, error) {
			return &quicwire.TPM2RandomRequest{NumBytes: r.GetNumBytes()}, nil
		}),
	platformv1.TPMService_MakeCredential_FullMethodName: requestEncoder(platformv1.TPMService_MakeCredential_FullMethodName,
		func(r *platformv1.MakeCredentialRequest) (interface{}, error) {
			return &quicwire.TPM2MakeCredentialRequest{
				AKName: r.GetAkName(),
				Secret: r.GetSecret(),
				EKCert: r.GetEkCert(),
				IAKPub: r.GetIakPub(),
			}, nil
		}),
	platformv1.TPMService_ActivateCredential_FullMethodName: requestEncoder(platformv1.TPMService_ActivateCredential_FullMethodName,
		func(r *platformv1.TPMActivateCredentialRequest) (interface{}, error) {
			return &quicwire.TPM2ActivateCredentialRequest{
				CredentialBlob:  r.GetCredentialBlob(),
				EncryptedSecret: r.GetEncryptedSecret(),
			}, nil
		}),
}

var tpmOpsResponseDecoders = map[string]categoryResponseDecoder{
	platformv1.TPMService_GetEventLog_FullMethodName: responseDecoder(platformv1.TPMService_GetEventLog_FullMethodName,
		func(w *quicwire.TPM2EventLogResponse, out *platformv1.GetEventLogResponse) error {
			out.EventLog = w.EventLog
			out.Format = w.Format
			out.EventCount = w.EventCount
			out.Entries = make([]*platformv1.EventLogEntry, 0, len(w.Entries))
			for _, e := range w.Entries {
				digests := make([]*platformv1.EventDigest, 0, len(e.Digests))
				for _, d := range e.Digests {
					digests = append(digests, &platformv1.EventDigest{AlgorithmId: d.AlgorithmID, Digest: d.Digest})
				}
				out.Entries = append(out.Entries, &platformv1.EventLogEntry{
					EventNum:    e.EventNum,
					PcrIndex:    e.PCRIndex,
					EventType:   e.EventType,
					DigestCount: e.DigestCount,
					Digests:     digests,
					EventSize:   e.EventSize,
					EventString: e.EventString,
				})
			}
			return nil
		}),
	platformv1.TPMService_GetRandom_FullMethodName: responseDecoder(platformv1.TPMService_GetRandom_FullMethodName,
		func(w *quicwire.TPM2RandomResponse, out *platformv1.GetRandomResponse) error {
			out.RandomBytes = w.RandomBytes
			return nil
		}),
	platformv1.TPMService_MakeCredential_FullMethodName: responseDecoder(platformv1.TPMService_MakeCredential_FullMethodName,
		func(w *quicwire.TPM2MakeCredentialResponse, out *platformv1.MakeCredentialResponse) error {
			out.CredentialBlob = w.CredentialBlob
			out.EncryptedSecret = w.EncryptedSecret
			out.Secret = w.Secret
			return nil
		}),
	platformv1.TPMService_ActivateCredential_FullMethodName: responseDecoder(platformv1.TPMService_ActivateCredential_FullMethodName,
		func(w *quicwire.TPM2ActivateCredentialResponse, out *platformv1.TPMActivateCredentialResponse) error {
			out.Secret = w.Secret
			return nil
		}),
}

func init() {
	categoryEmptyBodyMethods[platformv1.TPMService_GetEventLog_FullMethodName] = struct{}{}
	registerCategoryCodecs(tpmOpsRequestEncoders, tpmOpsResponseDecoders)
}
