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
	"strings"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The server's GetManifest reply carries int64 Unix timestamps and
// hash-algorithm strings, which the generic codec cannot decode into the
// protobuf HostManifest (timestamppb.Timestamp and enum fields). These
// mirror structs carry the server's codec tags, which are the wire contract.
func init() {
	methodRequestEncoders[platformv1.AttestationService_GetManifest_FullMethodName] = encodeGetManifestRequest
	methodResponseDecoders[platformv1.AttestationService_GetManifest_FullMethodName] = decodeGetManifestReply
}

// manifestGetRequestWire mirrors the server's GetManifestRequest in
// pkg/api/quic: the Go field name ID and its codec tag are the wire contract.
type manifestGetRequestWire struct {
	ID string `codec:"id"`
}

// encodeGetManifestRequest maps the protobuf request (field Id) onto the
// server's request shape (field ID).
func encodeGetManifestRequest(args interface{}) (interface{}, error) {
	in, ok := args.(*platformv1.GetManifestRequest)
	if !ok {
		return nil, ErrInvalidArgsType{Method: platformv1.AttestationService_GetManifest_FullMethodName}
	}
	return &manifestGetRequestWire{ID: in.GetId()}, nil
}

type manifestGetWire struct {
	Manifest  *manifestWire `codec:"manifest"`
	Timestamp int64         `codec:"timestamp"`
}

type manifestWire struct {
	ID                 string                `codec:"id"`
	HostID             string                `codec:"host_id"`
	Timestamp          int64                 `codec:"timestamp"`
	Nonce              []byte                `codec:"nonce"`
	Host               *hostAttestationWire  `codec:"host"`
	VMs                []vmAttestationWire   `codec:"vms"`
	Containers         []containerAttestWire `codec:"containers"`
	MerkleRoot         []byte                `codec:"merkle_root"`
	Signature          []byte                `codec:"signature"`
	SignatureAlgorithm string                `codec:"signature_algorithm"`
	Version            string                `codec:"version"`
	Metadata           map[string]string     `codec:"metadata"`
}

type hostAttestationWire struct {
	QuoteData          []byte         `codec:"quote_data"`
	Signature          []byte         `codec:"signature"`
	SignatureAlgorithm string         `codec:"signature_algorithm"`
	PCRs               []pcrValueWire `codec:"pcrs"`
	PCRDigest          []byte         `codec:"pcr_digest"`
	Nonce              []byte         `codec:"nonce"`
	Timestamp          int64          `codec:"timestamp"`
	AKPublicKey        []byte         `codec:"ak_public_key"`
	IDevIDCertificate  []byte         `codec:"idevid_certificate"`
	HashAlgorithm      string         `codec:"hash_algorithm"`
	FirmwareVersion    string         `codec:"firmware_version"`
}

type vmAttestationWire struct {
	VMID               string            `codec:"vm_id"`
	HostID             string            `codec:"host_id"`
	QuoteData          []byte            `codec:"quote_data"`
	Signature          []byte            `codec:"signature"`
	SignatureAlgorithm string            `codec:"signature_algorithm"`
	PCRs               []pcrValueWire    `codec:"pcrs"`
	PCRDigest          []byte            `codec:"pcr_digest"`
	Nonce              []byte            `codec:"nonce"`
	Timestamp          int64             `codec:"timestamp"`
	AIKPublicKey       []byte            `codec:"aik_public_key"`
	EKCertificate      []byte            `codec:"ek_certificate"`
	WorkloadPCR        []byte            `codec:"workload_pcr"`
	HashAlgorithm      string            `codec:"hash_algorithm"`
	Metadata           map[string]string `codec:"metadata"`
}

type containerAttestWire struct {
	ContainerID string            `codec:"container_id"`
	ImageID     string            `codec:"image_id"`
	ImageDigest string            `codec:"image_digest"`
	Digest      []byte            `codec:"digest"`
	PCRValue    []byte            `codec:"pcr_value"`
	Timestamp   int64             `codec:"timestamp"`
	Metadata    map[string]string `codec:"metadata"`
}

type pcrValueWire struct {
	Index     int    `codec:"index"`
	Value     []byte `codec:"value"`
	Algorithm string `codec:"algorithm"`
}

func (w *manifestWire) toProto() *platformv1.HostManifest {
	m := &platformv1.HostManifest{
		Id:                 w.ID,
		HostId:             w.HostID,
		Timestamp:          unixSecondsTimestamp(w.Timestamp),
		Nonce:              w.Nonce,
		Host:               w.Host.toProto(),
		MerkleRoot:         w.MerkleRoot,
		Signature:          w.Signature,
		SignatureAlgorithm: w.SignatureAlgorithm,
		Version:            w.Version,
		Metadata:           w.Metadata,
	}
	for i := range w.VMs {
		m.Vms = append(m.Vms, w.VMs[i].toProto())
	}
	for i := range w.Containers {
		m.Containers = append(m.Containers, w.Containers[i].toProto())
	}
	return m
}

func (w *hostAttestationWire) toProto() *platformv1.HostAttestation {
	if w == nil {
		return nil
	}
	return &platformv1.HostAttestation{
		QuoteData:          w.QuoteData,
		Signature:          w.Signature,
		SignatureAlgorithm: w.SignatureAlgorithm,
		Pcrs:               pcrValuesToProto(w.PCRs),
		PcrDigest:          w.PCRDigest,
		Nonce:              w.Nonce,
		Timestamp:          unixSecondsTimestamp(w.Timestamp),
		AkPublicKey:        w.AKPublicKey,
		IdevidCertificate:  w.IDevIDCertificate,
		HashAlgorithm:      attestationHashAlgorithm(w.HashAlgorithm),
		FirmwareVersion:    w.FirmwareVersion,
	}
}

func (w *vmAttestationWire) toProto() *platformv1.VMAttestation {
	return &platformv1.VMAttestation{
		VmId:               w.VMID,
		HostId:             w.HostID,
		QuoteData:          w.QuoteData,
		Signature:          w.Signature,
		SignatureAlgorithm: w.SignatureAlgorithm,
		Pcrs:               pcrValuesToProto(w.PCRs),
		PcrDigest:          w.PCRDigest,
		Nonce:              w.Nonce,
		Timestamp:          unixSecondsTimestamp(w.Timestamp),
		AikPublicKey:       w.AIKPublicKey,
		EkCertificate:      w.EKCertificate,
		WorkloadPcr:        w.WorkloadPCR,
		HashAlgorithm:      attestationHashAlgorithm(w.HashAlgorithm),
		Metadata:           w.Metadata,
	}
}

func (w *containerAttestWire) toProto() *platformv1.ContainerAttestation {
	return &platformv1.ContainerAttestation{
		ContainerId: w.ContainerID,
		ImageId:     w.ImageID,
		ImageDigest: w.ImageDigest,
		Digest:      w.Digest,
		PcrValue:    w.PCRValue,
		Timestamp:   unixSecondsTimestamp(w.Timestamp),
		Metadata:    w.Metadata,
	}
}

func (w *pcrValueWire) toProto() *platformv1.AttestationPCRValue {
	return &platformv1.AttestationPCRValue{
		Index:     uint32(w.Index),
		Value:     w.Value,
		Algorithm: attestationHashAlgorithm(w.Algorithm),
	}
}

func pcrValuesToProto(in []pcrValueWire) []*platformv1.AttestationPCRValue {
	if len(in) == 0 {
		return nil
	}
	out := make([]*platformv1.AttestationPCRValue, 0, len(in))
	for i := range in {
		out = append(out, in[i].toProto())
	}
	return out
}

// unixSecondsTimestamp converts a wire Unix time in seconds; 0 means unset.
func unixSecondsTimestamp(ts int64) *timestamppb.Timestamp {
	if ts == 0 {
		return nil
	}
	return timestamppb.New(time.Unix(ts, 0))
}

// attestationHashAlgorithm maps the server's hash-algorithm string to the enum.
func attestationHashAlgorithm(s string) platformv1.AttestationHashAlgorithm {
	switch strings.ToLower(s) {
	case "sha1":
		return platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA1
	case "sha256":
		return platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256
	case "sha384":
		return platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA384
	case "sha512":
		return platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA512
	default:
		return platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_UNSPECIFIED
	}
}

func decodeGetManifestReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.GetManifestResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.AttestationService_GetManifest_FullMethodName}
	}
	var wire manifestGetWire
	if err := quicwire.DecodePayload(payload, &wire); err != nil {
		return ErrDecodingFailed{Err: err}
	}
	if wire.Manifest == nil {
		out.Manifest = nil
		return nil
	}
	out.Manifest = wire.Manifest.toProto()
	return nil
}
