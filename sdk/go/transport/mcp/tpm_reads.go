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

package mcp

// TPM read mapping for the MCP transport (#1690).
//
// platform_tpm_ek, platform_tpm_ek_cert and platform_tpm_eventlog take no
// arguments: the first two read the platform's own EK, so a request that
// names another key (a handle or an algorithm) is refused before any call
// goes out, and the event-log tool always answers the raw TCG2 log.
// platform_tpm_srk takes the handle (0 is the SSRK). platform_tpm_ek and
// platform_tpm_srk answer {handle, public_key, algorithm}, where algorithm is
// the x509 family name ("RSA", "ECDSA") and not the pb enum, so the key
// fields are decoded by hand. platform_tpm_ek_cert answers the DER
// certificate as base64, with no format field. platform_tpm_pcrs nests the
// values per bank ({banks: [{algorithm, pcrs: [{index, value}]}]}), which is
// flattened into the reply's PCR values. platform_tpm_random fits the generic
// path (num_bytes in, random_bytes back as base64) and needs only its route.

import (
	"fmt"
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func init() {
	for method, tool := range map[string]string{
		platformv1.TPMService_GetEK_FullMethodName:            "platform_tpm_ek",
		platformv1.TPMService_GetEKCertificate_FullMethodName: "platform_tpm_ek_cert",
		platformv1.TPMService_GetSRK_FullMethodName:           "platform_tpm_srk",
		platformv1.TPMService_GetPCRs_FullMethodName:          "platform_tpm_pcrs",
		platformv1.TPMService_GetEventLog_FullMethodName:      "platform_tpm_eventlog",
		platformv1.TPMService_GetRandom_FullMethodName:        "platform_tpm_random",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}

	for method, build := range map[string]mcpArgBuilder{
		platformv1.TPMService_GetEK_FullMethodName:            buildTPMReadEKArgs,
		platformv1.TPMService_GetEKCertificate_FullMethodName: buildTPMReadEKCertificateArgs,
		platformv1.TPMService_GetSRK_FullMethodName:           buildTPMReadSRKArgs,
		platformv1.TPMService_GetPCRs_FullMethodName:          buildTPMReadPCRsArgs,
		platformv1.TPMService_GetEventLog_FullMethodName:      buildTPMReadEventLogArgs,
	} {
		mcpArgBuilders[method] = build
	}

	for method, decode := range map[string]mcpReplyDecoder{
		platformv1.TPMService_GetEK_FullMethodName:       decodeTPMReadEKResult,
		platformv1.TPMService_GetSRK_FullMethodName:      decodeTPMReadSRKResult,
		platformv1.TPMService_GetEventLog_FullMethodName: decodeTPMReadEventLogResult,
	} {
		mcpReplyDecoders[method] = decode
	}

	for method, decode := range map[string]mcpRequestReplyDecoder{
		platformv1.TPMService_GetEKCertificate_FullMethodName: decodeTPMReadEKCertificateResult,
		platformv1.TPMService_GetPCRs_FullMethodName:          decodeTPMReadPCRsResult,
	} {
		mcpRequestReplyDecoders[method] = decode
	}
}

// ErrTPMReadFieldUnsupported reports a TPM read request field the MCP tool
// cannot honour, because the tool reads the platform's own key.
type ErrTPMReadFieldUnsupported struct {
	Method string
	Field  string
}

func (e ErrTPMReadFieldUnsupported) Error() string {
	return fmt.Sprintf("%s: %s is not supported over MCP; the tool reads the platform key", e.Method, e.Field)
}

// buildTPMReadEKArgs refuses a request for any key but the platform EK; the
// platform_tpm_ek tool takes no arguments.
func buildTPMReadEKArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.GetEKRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.TPMService_GetEK_FullMethodName}
	}
	return tpmReadPlatformKeyArgs(platformv1.TPMService_GetEK_FullMethodName, in.GetHandle(), in.GetAlgorithm())
}

// buildTPMReadEKCertificateArgs refuses a request for any certificate but the
// platform EK's; the platform_tpm_ek_cert tool takes no arguments.
func buildTPMReadEKCertificateArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.GetEKCertificateRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.TPMService_GetEKCertificate_FullMethodName}
	}
	return tpmReadPlatformKeyArgs(platformv1.TPMService_GetEKCertificate_FullMethodName, in.GetHandle(), in.GetAlgorithm())
}

// tpmReadPlatformKeyArgs answers the empty argument set of a platform-key
// tool, or ErrTPMReadFieldUnsupported when the request names another key.
func tpmReadPlatformKeyArgs(method string, handle uint32, algorithm platformv1.KeyAlgorithm) (map[string]interface{}, error) {
	if handle != 0 {
		return nil, ErrTPMReadFieldUnsupported{Method: method, Field: "handle"}
	}
	if algorithm != platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED {
		return nil, ErrTPMReadFieldUnsupported{Method: method, Field: "algorithm"}
	}
	return map[string]interface{}{}, nil
}

// buildTPMReadSRKArgs sends the SRK handle (0 is the SSRK) and refuses an
// algorithm, which the platform_tpm_srk tool does not take.
func buildTPMReadSRKArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.GetSRKRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.TPMService_GetSRK_FullMethodName}
	}
	if in.GetAlgorithm() != platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED {
		return nil, ErrTPMReadFieldUnsupported{Method: platformv1.TPMService_GetSRK_FullMethodName, Field: "algorithm"}
	}
	return map[string]interface{}{"handle": in.GetHandle()}, nil
}

// buildTPMReadPCRsArgs sends the PCR indices (empty reads all 24). The bank
// filter is applied to the reply, as the tool answers every bank.
func buildTPMReadPCRsArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.GetPCRsRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.TPMService_GetPCRs_FullMethodName}
	}
	indices := in.GetIndices()
	if indices == nil {
		indices = []uint32{}
	}
	return map[string]interface{}{"indices": indices}, nil
}

// buildTPMReadEventLogArgs sends no arguments: the platform_tpm_eventlog tool
// always answers the raw TCG2 log, so the request's format is not sent.
func buildTPMReadEventLogArgs(args interface{}) (map[string]interface{}, error) {
	if _, ok := args.(*platformv1.GetEventLogRequest); !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.TPMService_GetEventLog_FullMethodName}
	}
	return map[string]interface{}{}, nil
}

// tpmReadKeyResult is the platform_tpm_ek and platform_tpm_srk result. The
// tool's algorithm is the x509 family name only ("RSA", "ECDSA"), without the
// key size the pb KeyAlgorithm enum needs, so it is not decoded and the
// reply's Algorithm stays unset.
type tpmReadKeyResult struct {
	Handle    uint32 `json:"handle"`
	PublicKey []byte `json:"public_key"`
}

// decodeTPMReadEKResult carries the EK handle and public key.
func decodeTPMReadEKResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetEKResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_GetEK_FullMethodName}
	}
	var key tpmReadKeyResult
	if err := mapToStruct(result, &key); err != nil {
		return err
	}
	out.Handle = key.Handle
	out.PublicKey = key.PublicKey
	return nil
}

// decodeTPMReadSRKResult carries the SRK handle and public key.
func decodeTPMReadSRKResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetSRKResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_GetSRK_FullMethodName}
	}
	var key tpmReadKeyResult
	if err := mapToStruct(result, &key); err != nil {
		return err
	}
	out.Handle = key.Handle
	out.PublicKey = key.PublicKey
	return nil
}

// tpmReadEKCertificateResult is the platform_tpm_ek_cert result: the DER
// certificate as base64.
type tpmReadEKCertificateResult struct {
	Certificate []byte `json:"certificate"`
}

// decodeTPMReadEKCertificateResult carries the DER certificate.
func decodeTPMReadEKCertificateResult(_ interface{}, result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetEKCertificateResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_GetEKCertificate_FullMethodName}
	}
	var cert tpmReadEKCertificateResult
	if err := mapToStruct(result, &cert); err != nil {
		return err
	}
	out.Certificate = cert.Certificate
	out.Format = "DER"
	return nil
}

// tpmReadPCRsResult is the platform_tpm_pcrs result. A bank's algorithm is
// decoded loosely: the tool may report a name or a TCG algorithm id.
type tpmReadPCRsResult struct {
	Banks []struct {
		Algorithm interface{} `json:"algorithm"`
		PCRs      []struct {
			Index uint32 `json:"index"`
			Value []byte `json:"value"`
		} `json:"pcrs"`
	} `json:"banks"`
}

// decodeTPMReadPCRsResult flattens the tool's banks into the reply's PCR
// values, in the tool's order, keeping only the requested bank when the
// request names one.
func decodeTPMReadPCRsResult(args interface{}, result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetPCRsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_GetPCRs_FullMethodName}
	}
	want := platformv1.PCRBank_PCR_BANK_UNSPECIFIED
	if in, ok := args.(*platformv1.GetPCRsRequest); ok {
		want = in.GetBank()
	}
	var pcrs tpmReadPCRsResult
	if err := mapToStruct(result, &pcrs); err != nil {
		return err
	}
	out.PcrValues = nil
	for _, bank := range pcrs.Banks {
		name := tpmReadPCRBank(bank.Algorithm)
		if want != platformv1.PCRBank_PCR_BANK_UNSPECIFIED && name != want {
			continue
		}
		for _, pcr := range bank.PCRs {
			out.PcrValues = append(out.PcrValues, &platformv1.PCRValue{Index: pcr.Index, Bank: name, Value: pcr.Value})
		}
	}
	return nil
}

// tpmReadPCRBank maps a bank algorithm, a name compared case-insensitively
// with or without "-" or "_", or a TCG algorithm id, onto the pb bank.
// Anything else is PCR_BANK_UNSPECIFIED.
func tpmReadPCRBank(algorithm interface{}) platformv1.PCRBank {
	switch v := algorithm.(type) {
	case string:
		name := strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(v))
		switch name {
		case "sha1":
			return platformv1.PCRBank_PCR_BANK_SHA1
		case "sha256":
			return platformv1.PCRBank_PCR_BANK_SHA256
		case "sha384":
			return platformv1.PCRBank_PCR_BANK_SHA384
		case "sha512":
			return platformv1.PCRBank_PCR_BANK_SHA512
		case "sm3256":
			return platformv1.PCRBank_PCR_BANK_SM3_256
		}
	case float64:
		switch v {
		case 0x0004:
			return platformv1.PCRBank_PCR_BANK_SHA1
		case 0x000B:
			return platformv1.PCRBank_PCR_BANK_SHA256
		case 0x000C:
			return platformv1.PCRBank_PCR_BANK_SHA384
		case 0x000D:
			return platformv1.PCRBank_PCR_BANK_SHA512
		case 0x0012:
			return platformv1.PCRBank_PCR_BANK_SM3_256
		}
	}
	return platformv1.PCRBank_PCR_BANK_UNSPECIFIED
}

// tpmReadEventLogResult is the platform_tpm_eventlog result. The tool sends
// the parsed entries with the fields of the pb EventLogEntry (absent, like
// event_count, when the daemon cannot parse the log).
type tpmReadEventLogResult struct {
	EventLog   []byte                 `json:"event_log"`
	Format     string                 `json:"format"`
	EventCount uint64                 `json:"event_count"`
	Entries    []tpmReadEventLogEntry `json:"entries"`
}

// tpmReadEventLogEntry is one parsed event of the platform_tpm_eventlog result.
type tpmReadEventLogEntry struct {
	EventNum    uint32 `json:"event_num"`
	PCRIndex    uint32 `json:"pcr_index"`
	EventType   string `json:"event_type"`
	DigestCount uint32 `json:"digest_count"`
	Digests     []struct {
		AlgorithmID string `json:"algorithm_id"`
		Digest      string `json:"digest"`
	} `json:"digests"`
	EventSize   uint32 `json:"event_size"`
	EventString string `json:"event_string"`
}

// decodeTPMReadEventLogResult carries the raw log, its format and its event
// count.
func decodeTPMReadEventLogResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetEventLogResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_GetEventLog_FullMethodName}
	}
	var log tpmReadEventLogResult
	if err := mapToStruct(result, &log); err != nil {
		return err
	}
	out.EventLog = log.EventLog
	out.Format = log.Format
	out.EventCount = log.EventCount
	out.Entries = nil
	for _, e := range log.Entries {
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
}
