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

// Package tpmnv contains the single, transport-level implementation of
// the TPM 2.0 NVRAM commands (NVDefineSpace / NVWrite / NVRead /
// NVUndefineSpace) shared by every daemon transport (gRPC, QUIC, …).
//
// The TrustedPlatformModule interface does not expose NV operations
// directly, so the gRPC TPMService, the QUIC TPM2 handler and the MCP
// provider reach them through the module's raw go-tpm transport
// (TrustedPlatformModule.Transport()). Keeping the command construction
// and argument validation here guarantees exactly one wire
// implementation, identical auth-hierarchy dispatch and the same typed
// errors across protocols. Every function is device-agnostic: it behaves identically
// against a hardware TPM (/dev/tpmrm0) and swtpm because the transport
// abstraction hides the underlying device.
package tpmnv

import (
	tpmgo "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// maxNVChunk caps a single NVRead / NVWrite frame. TPM_PT_NV_BUFFER_MAX
// varies wildly between vendors (Infineon SLB9665 reports as little as 7
// bytes in one mode, 1024 in another); a conservative 512-byte cap is
// what go-xkms's own EK-certificate path and tpm2-tools default to.
const maxNVChunk = 512

// Read reads size bytes (0 means the index's full declared DataSize)
// from the NV index starting at offset, using the supplied password for
// authorization. The auth hierarchy is chosen from the index's public
// attributes: AUTHREAD authorizes against the index's own AuthValue,
// OWNERREAD routes through the owner hierarchy, PPREAD through the
// platform hierarchy. Reads larger than maxNVChunk are chunked. The read
// is clamped to the index's DataSize, so it needs no CheckSpan: a size
// past the end reads to the end.
func Read(tr transport.TPM, index uint32, size, offset uint16, password []byte) ([]byte, error) {
	if err := checkTarget(tr, index); err != nil {
		return nil, err
	}
	nvHandle := tpmgo.TPMHandle(index)
	pubRsp, err := tpmgo.NVReadPublic{NVIndex: nvHandle}.Execute(tr)
	if err != nil {
		return nil, err
	}
	pub, err := pubRsp.NVPublic.Contents()
	if err != nil {
		return nil, err
	}

	dataSize := uint16(pub.DataSize)
	if size > 0 && size < dataSize {
		dataSize = size
	}

	authHandle := readAuthHandle(pub, nvHandle, pubRsp.NVName, password)

	out := make([]byte, 0, dataSize)
	for read := uint16(0); read < dataSize; {
		chunk := dataSize - read
		if chunk > maxNVChunk {
			chunk = maxNVChunk
		}
		readRsp, err := tpmgo.NVRead{
			AuthHandle: authHandle,
			NVIndex: tpmgo.AuthHandle{
				Handle: nvHandle,
				Name:   pubRsp.NVName,
				Auth:   tpmgo.PasswordAuth(password),
			},
			Size:   chunk,
			Offset: offset + read,
		}.Execute(tr)
		if err != nil {
			return nil, err
		}
		out = append(out, readRsp.Data.Buffer...)
		read += chunk
	}
	return out, nil
}

// Write writes data to the NV index starting at offset, using password
// for authorization. The auth hierarchy is chosen from the index's
// public attributes (AUTHWRITE / OWNERWRITE / PPWRITE). Writes larger
// than maxNVChunk are chunked. Empty data is rejected, and so is data
// that would run past MaxSpan, before any chunk is written.
func Write(tr transport.TPM, index uint32, data []byte, offset uint16, password []byte) error {
	if index == 0 {
		return ErrIndexRequired{}
	}
	if len(data) == 0 {
		return ErrDataRequired{}
	}
	if err := CheckSpan(uint32(offset), uint64(len(data))); err != nil {
		return err
	}
	if err := checkTarget(tr, index); err != nil {
		return err
	}
	nvHandle := tpmgo.TPMHandle(index)
	pubRsp, err := tpmgo.NVReadPublic{NVIndex: nvHandle}.Execute(tr)
	if err != nil {
		return err
	}
	pub, err := pubRsp.NVPublic.Contents()
	if err != nil {
		return err
	}

	authHandle := writeAuthHandle(pub, nvHandle, pubRsp.NVName, password)

	for i := 0; i < len(data); {
		end := i + maxNVChunk
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		if _, err := (tpmgo.NVWrite{
			AuthHandle: authHandle,
			NVIndex: tpmgo.AuthHandle{
				Handle: nvHandle,
				Name:   pubRsp.NVName,
				Auth:   tpmgo.PasswordAuth(password),
			},
			Data:   tpmgo.TPM2BMaxNVBuffer{Buffer: chunk},
			Offset: offset + uint16(i),
		}).Execute(tr); err != nil {
			return err
		}
		i = end
	}
	return nil
}

// Define allocates a new owner-hierarchy NV index of the given size with
// the supplied TPMA_NV attribute names (see BuildAttributes). nvAuth is
// the auth value bound to the new index; ownerAuth authorizes the owner
// hierarchy.
func Define(tr transport.TPM, index uint32, size uint16, attrNames []string, nvAuth, ownerAuth []byte) error {
	define := tpmgo.NVDefineSpace{
		AuthHandle: tpmgo.AuthHandle{
			Handle: tpmgo.TPMRHOwner,
			Auth:   tpmgo.PasswordAuth(ownerAuth),
		},
		Auth: tpmgo.TPM2BAuth{Buffer: nvAuth},
		PublicInfo: tpmgo.New2B(tpmgo.TPMSNVPublic{
			NVIndex:    tpmgo.TPMHandle(index),
			NameAlg:    tpmgo.TPMAlgSHA256,
			Attributes: BuildAttributes(attrNames),
			DataSize:   size,
		}),
	}
	_, err := define.Execute(tr)
	return err
}

// Undefine frees an owner-hierarchy NV index. ownerAuth authorizes the
// owner hierarchy.
func Undefine(tr transport.TPM, index uint32, ownerAuth []byte) error {
	if err := checkTarget(tr, index); err != nil {
		return err
	}
	nvHandle := tpmgo.TPMHandle(index)
	pubRsp, err := tpmgo.NVReadPublic{NVIndex: nvHandle}.Execute(tr)
	if err != nil {
		return err
	}
	_, err = tpmgo.NVUndefineSpace{
		AuthHandle: tpmgo.AuthHandle{
			Handle: tpmgo.TPMRHOwner,
			Auth:   tpmgo.PasswordAuth(ownerAuth),
		},
		NVIndex: tpmgo.NamedHandle{
			Handle: nvHandle,
			Name:   pubRsp.NVName,
		},
	}.Execute(tr)
	return err
}

// readAuthHandle selects the read auth hierarchy from the index's public
// attributes. AUTHREAD is the common case (index-self auth); OWNERREAD
// and PPREAD route through the owner / platform hierarchy respectively.
// Password converts a request password to the auth value go-tpm sends.
// An empty password becomes nil so no transport has to repeat the
// conversion.
func Password(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}

// checkTarget rejects index 0, a handle outside the NV index range and a
// TPM without a raw transport before any command is framed.
func checkTarget(tr transport.TPM, index uint32) error {
	if index == 0 {
		return ErrIndexRequired{}
	}
	if err := CheckIndex(index); err != nil {
		return err
	}
	if tr == nil {
		return ErrTransportUnavailable{}
	}
	return nil
}

func readAuthHandle(pub *tpmgo.TPMSNVPublic, nvHandle tpmgo.TPMHandle, name tpmgo.TPM2BName, password []byte) tpmgo.AuthHandle {
	switch {
	case pub.Attributes.OwnerRead && !pub.Attributes.AuthRead:
		return tpmgo.AuthHandle{Handle: tpmgo.TPMRHOwner, Auth: tpmgo.PasswordAuth(password)}
	case pub.Attributes.PPRead:
		return tpmgo.AuthHandle{Handle: tpmgo.TPMRHPlatform, Auth: tpmgo.PasswordAuth(password)}
	default:
		return tpmgo.AuthHandle{Handle: nvHandle, Name: name, Auth: tpmgo.PasswordAuth(password)}
	}
}

// writeAuthHandle selects the write auth hierarchy from the index's
// public attributes, mirroring readAuthHandle.
func writeAuthHandle(pub *tpmgo.TPMSNVPublic, nvHandle tpmgo.TPMHandle, name tpmgo.TPM2BName, password []byte) tpmgo.AuthHandle {
	switch {
	case pub.Attributes.OwnerWrite && !pub.Attributes.AuthWrite:
		return tpmgo.AuthHandle{Handle: tpmgo.TPMRHOwner, Auth: tpmgo.PasswordAuth(password)}
	case pub.Attributes.PPWrite:
		return tpmgo.AuthHandle{Handle: tpmgo.TPMRHPlatform, Auth: tpmgo.PasswordAuth(password)}
	default:
		return tpmgo.AuthHandle{Handle: nvHandle, Name: name, Auth: tpmgo.PasswordAuth(password)}
	}
}

// BuildAttributes converts a list of TPMA_NV attribute names into a
// TPMANV bitfield. Unknown names are ignored. With an empty list the
// defaults are an ordinary AuthRead+AuthWrite index with NoDA set so an
// operator cannot lock out the dictionary-attack hierarchy by
// experimenting with NV indices.
func BuildAttributes(names []string) tpmgo.TPMANV {
	if len(names) == 0 {
		return tpmgo.TPMANV{
			AuthRead:  true,
			AuthWrite: true,
			NT:        tpmgo.TPMNTOrdinary,
			NoDA:      true,
		}
	}
	a := tpmgo.TPMANV{NT: tpmgo.TPMNTOrdinary, NoDA: true}
	for _, n := range names {
		switch n {
		case "AUTHREAD":
			a.AuthRead = true
		case "AUTHWRITE":
			a.AuthWrite = true
		case "OWNERREAD":
			a.OwnerRead = true
		case "OWNERWRITE":
			a.OwnerWrite = true
		case "PPREAD":
			a.PPRead = true
		case "PPWRITE":
			a.PPWrite = true
		case "WRITELOCK":
			a.WriteDefine = true
		case "READLOCK":
			a.ReadSTClear = true
		case "NO_DA":
			a.NoDA = true
		case "DA":
			a.NoDA = false
		case "WRITTEN":
			a.Written = true
		case "WRITEALL":
			a.WriteAll = true
		case "GLOBALLOCK":
			a.GlobalLock = true
		case "POLICYREAD":
			a.PolicyRead = true
		case "POLICYWRITE":
			a.PolicyWrite = true
		}
	}
	return a
}
