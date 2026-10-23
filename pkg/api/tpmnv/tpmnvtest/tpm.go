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

// Package tpmnvtest provides an in-memory go-tpm transport that answers
// the NV commands package tpmnv frames (NV_ReadPublic, NV_Read, NV_Write,
// NV_UndefineSpace), so every transport's NV path can be tested in-process
// without a TPM, swtpm or cgo simulator.
package tpmnvtest

import (
	"bytes"
	"encoding/binary"
	"io"

	tpmgo "github.com/google/go-tpm/tpm2"
)

// rcSession1 marks a format-1 response code as raised by the first
// authorization session (TPM 2.0 Part 2, 6.6.3: RC_S + RC_1).
const rcSession1 = 0x900

// rcHandle1 marks a format-1 response code as raised by the first
// command handle (RC_H + RC_1).
const rcHandle1 = 0x100

// rcHandle2 marks a format-1 response code as raised by the second
// command handle (RC_H + RC_2).
const rcHandle2 = 0x200

// space is one defined NV index.
type space struct {
	public tpmgo.TPMSNVPublic
	auth   []byte
	data   []byte
}

// command is a parsed command frame.
type command struct {
	code     tpmgo.TPMCC
	handles  []uint32
	password []byte
	params   *bytes.Reader
	sessions bool
}

// TPM is an in-memory TPM 2.0 transport holding ordinary NV indexes. It
// enforces password authorization against the index's own auth value or
// the owner hierarchy's, as the index's attributes select. It is not safe
// for concurrent use.
type TPM struct {
	// OwnerAuth is the owner-hierarchy auth value.
	OwnerAuth []byte

	spaces map[uint32]*space
}

// New returns a TPM with no NV indexes and an empty owner auth.
func New() *TPM {
	return &TPM{spaces: make(map[uint32]*space)}
}

// Define creates an ordinary NV index of size bytes, zero-filled, with the
// given attributes and auth value.
func (t *TPM) Define(index uint32, size uint16, attrs tpmgo.TPMANV, auth []byte) {
	attrs.NT = tpmgo.TPMNTOrdinary
	t.spaces[index] = &space{
		public: tpmgo.TPMSNVPublic{
			NVIndex:    tpmgo.TPMHandle(index),
			NameAlg:    tpmgo.TPMAlgSHA256,
			Attributes: attrs,
			DataSize:   size,
		},
		auth: auth,
		data: make([]byte, size),
	}
}

// Data returns a copy of the index's contents, and false when the index
// is not defined.
func (t *TPM) Data(index uint32) ([]byte, bool) {
	s, ok := t.spaces[index]
	if !ok {
		return nil, false
	}
	return bytes.Clone(s.data), true
}

// Send executes one command frame and returns the response frame. A
// command this fake does not implement answers TPM_RC_COMMAND_CODE.
func (t *TPM) Send(frame []byte) ([]byte, error) {
	cmd, err := parseCommand(frame)
	if err != nil {
		return nil, err
	}
	handler, ok := handlers[cmd.code]
	if !ok {
		return failure(tpmgo.TPMRCCommandCode), nil
	}
	return handler(t, cmd)
}

// handlers dispatches each implemented command code.
var handlers = map[tpmgo.TPMCC]func(*TPM, *command) ([]byte, error){
	tpmgo.TPMCCNVReadPublic:    (*TPM).readPublic,
	tpmgo.TPMCCNVRead:          (*TPM).read,
	tpmgo.TPMCCNVWrite:         (*TPM).write,
	tpmgo.TPMCCNVUndefineSpace: (*TPM).undefine,
}

// Close implements transport.TPM.
func (t *TPM) Close() error { return nil }

func (t *TPM) readPublic(cmd *command) ([]byte, error) {
	s, ok := t.spaces[cmd.handles[0]]
	if !ok {
		return failure(tpmgo.TPMRCHandle + rcHandle1), nil
	}
	name, err := tpmgo.NVName(&s.public)
	if err != nil {
		return nil, err
	}
	params := append(tpmgo.Marshal(tpmgo.New2B(s.public)), tpmgo.Marshal(name)...)
	return success(false, params), nil
}

func (t *TPM) read(cmd *command) ([]byte, error) {
	s, rc := t.authorize(cmd)
	if rc != tpmgo.TPMRCSuccess {
		return failure(rc), nil
	}
	var size, offset uint16
	if err := readUint16s(cmd.params, &size, &offset); err != nil {
		return nil, err
	}
	if int(offset)+int(size) > len(s.data) {
		return failure(tpmgo.TPMRCNVRange), nil
	}
	data := s.data[offset : offset+size]
	return success(true, tpmgo.Marshal(tpmgo.TPM2BMaxNVBuffer{Buffer: data})), nil
}

func (t *TPM) write(cmd *command) ([]byte, error) {
	s, rc := t.authorize(cmd)
	if rc != tpmgo.TPMRCSuccess {
		return failure(rc), nil
	}
	data, err := readTPM2B(cmd.params)
	if err != nil {
		return nil, err
	}
	var offset uint16
	if err := readUint16s(cmd.params, &offset); err != nil {
		return nil, err
	}
	if int(offset)+len(data) > len(s.data) {
		return failure(tpmgo.TPMRCNVRange), nil
	}
	copy(s.data[offset:], data)
	return success(true, nil), nil
}

func (t *TPM) undefine(cmd *command) ([]byte, error) {
	if tpmgo.TPMHandle(cmd.handles[0]) != tpmgo.TPMRHOwner {
		return failure(tpmgo.TPMRCHierarchy + rcHandle1), nil
	}
	if !bytes.Equal(cmd.password, t.OwnerAuth) {
		return failure(tpmgo.TPMRCAuthFail + rcSession1), nil
	}
	index := cmd.handles[1]
	if _, ok := t.spaces[index]; !ok {
		return failure(tpmgo.TPMRCHandle + rcHandle2), nil
	}
	delete(t.spaces, index)
	return success(true, nil), nil
}

// authorize resolves the NV index an NV_Read / NV_Write targets and checks
// the session password against the auth handle the command names: the
// owner hierarchy, or the index itself.
func (t *TPM) authorize(cmd *command) (*space, tpmgo.TPMRC) {
	s, ok := t.spaces[cmd.handles[1]]
	if !ok {
		return nil, tpmgo.TPMRCHandle + rcHandle2
	}
	want := s.auth
	if tpmgo.TPMHandle(cmd.handles[0]) == tpmgo.TPMRHOwner {
		want = t.OwnerAuth
	}
	if !bytes.Equal(cmd.password, want) {
		return nil, tpmgo.TPMRCAuthFail + rcSession1
	}
	return s, tpmgo.TPMRCSuccess
}

// handleCounts is the number of command handles each implemented command
// carries.
var handleCounts = map[tpmgo.TPMCC]int{
	tpmgo.TPMCCNVReadPublic:    1,
	tpmgo.TPMCCNVRead:          2,
	tpmgo.TPMCCNVWrite:         2,
	tpmgo.TPMCCNVUndefineSpace: 2,
}

func parseCommand(frame []byte) (*command, error) {
	r := bytes.NewReader(frame)
	var hdr struct {
		Tag    uint16
		Length uint32
		Code   uint32
	}
	if err := binary.Read(r, binary.BigEndian, &hdr); err != nil {
		return nil, err
	}
	cmd := &command{
		code:     tpmgo.TPMCC(hdr.Code),
		handles:  make([]uint32, handleCounts[tpmgo.TPMCC(hdr.Code)]),
		sessions: tpmgo.TPMST(hdr.Tag) == tpmgo.TPMSTSessions,
	}
	if err := binary.Read(r, binary.BigEndian, cmd.handles); err != nil {
		return nil, err
	}
	if cmd.sessions {
		password, err := readPasswordSession(r)
		if err != nil {
			return nil, err
		}
		cmd.password = password
	}
	cmd.params = r
	return cmd, nil
}

// readPasswordSession reads the authorization area and returns the first
// session's authorization value, which for a password session is the
// password itself.
func readPasswordSession(r *bytes.Reader) ([]byte, error) {
	var areaSize uint32
	if err := binary.Read(r, binary.BigEndian, &areaSize); err != nil {
		return nil, err
	}
	area := make([]byte, areaSize)
	if _, err := io.ReadFull(r, area); err != nil {
		return nil, err
	}
	session := bytes.NewReader(area)
	var handle uint32
	if err := binary.Read(session, binary.BigEndian, &handle); err != nil {
		return nil, err
	}
	if _, err := readTPM2B(session); err != nil {
		return nil, err
	}
	if _, err := session.ReadByte(); err != nil {
		return nil, err
	}
	return readTPM2B(session)
}

func readTPM2B(r *bytes.Reader) ([]byte, error) {
	var size uint16
	if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func readUint16s(r *bytes.Reader, values ...*uint16) error {
	for _, v := range values {
		if err := binary.Read(r, binary.BigEndian, v); err != nil {
			return err
		}
	}
	return nil
}

// success frames a successful response. A command sent with sessions gets
// the parameter-size field and one password-session response.
func success(sessions bool, params []byte) []byte {
	body := params
	tag := tpmgo.TPMSTNoSessions
	if sessions {
		tag = tpmgo.TPMSTSessions
		body = binary.BigEndian.AppendUint32(nil, uint32(len(params)))
		body = append(body, params...)
		body = append(body, tpmgo.Marshal(tpmgo.TPMSAuthResponse{
			Attributes: tpmgo.TPMASession{ContinueSession: true},
		})...)
	}
	return frame(tag, tpmgo.TPMRCSuccess, body)
}

// failure frames an error response carrying rc.
func failure(rc tpmgo.TPMRC) []byte {
	return frame(tpmgo.TPMSTNoSessions, rc, nil)
}

func frame(tag tpmgo.TPMST, rc tpmgo.TPMRC, body []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, uint16(tag))
	out = binary.BigEndian.AppendUint32(out, uint32(10+len(body)))
	out = binary.BigEndian.AppendUint32(out, uint32(rc))
	return append(out, body...)
}
