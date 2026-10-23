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

package nbd

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
)

// transmission is the data phase of one connection: it serves block
// requests against the client's own volume until NBD_CMD_DISC.
type transmission struct {
	conn     net.Conn
	identity string
	vol      *volume
	logger   *slog.Logger

	writer *bufio.Writer
	// buf is reused across requests and grows to the largest payload seen.
	buf []byte
}

// request is one decoded transmission request header.
type request struct {
	flags   uint16
	command uint16
	handle  uint64
	offset  uint64
	length  uint32
}

// commandResult is a handler's answer: the NBD error code and, for a
// successful READ, the data. disconnect ends the session without a reply.
type commandResult struct {
	code       uint32
	data       []byte
	disconnect bool
}

type commandHandler func(t *transmission, req request) (commandResult, error)

// commands dispatches each supported command. A handler returns an error
// only when the session cannot continue; a failed request is an NBD error
// code in its result.
var commands = map[uint16]commandHandler{
	cmdRead:  (*transmission).read,
	cmdWrite: (*transmission).write,
	cmdDisc:  (*transmission).disconnect,
	cmdFlush: (*transmission).flush,
	cmdTrim:  (*transmission).trim,
}

// run serves requests until the client disconnects or the connection fails.
func (t *transmission) run() error {
	t.writer = bufio.NewWriterSize(t.conn, 64<<10)
	for {
		req, err := t.readRequest()
		if err != nil {
			return err
		}

		handler, ok := commands[req.command]
		if !ok {
			handler = (*transmission).unsupported
		}
		result, err := handler(t, req)
		if err != nil {
			return err
		}
		if result.disconnect {
			return t.close()
		}
		if err := t.sendReply(req.handle, result); err != nil {
			return err
		}
	}
}

// readRequest reads one request header.
func (t *transmission) readRequest() (request, error) {
	var header [requestHeaderLength]byte
	if _, err := io.ReadFull(t.conn, header[:]); err != nil {
		return request{}, ErrProtocol{Reason: "read request header", Cause: err}
	}
	if binary.BigEndian.Uint32(header[0:4]) != requestMagic {
		return request{}, ErrProtocol{Reason: "bad request magic"}
	}
	return request{
		flags:   binary.BigEndian.Uint16(header[4:6]),
		command: binary.BigEndian.Uint16(header[6:8]),
		handle:  binary.BigEndian.Uint64(header[8:16]),
		offset:  binary.BigEndian.Uint64(header[16:24]),
		length:  binary.BigEndian.Uint32(header[24:28]),
	}, nil
}

// sendReply writes a simple reply, followed by the data of a successful READ.
func (t *transmission) sendReply(handle uint64, result commandResult) error {
	var header [16]byte
	binary.BigEndian.PutUint32(header[0:4], simpleReplyMagic)
	binary.BigEndian.PutUint32(header[4:8], result.code)
	binary.BigEndian.PutUint64(header[8:16], handle)
	if _, err := t.writer.Write(header[:]); err != nil {
		return ErrProtocol{Reason: "write reply", Cause: err}
	}
	if result.code == errNone && len(result.data) > 0 {
		if _, err := t.writer.Write(result.data); err != nil {
			return ErrProtocol{Reason: "write reply data", Cause: err}
		}
	}
	if err := t.writer.Flush(); err != nil {
		return ErrProtocol{Reason: "write reply", Cause: err}
	}
	return nil
}

// buffer returns t.buf resized to length.
func (t *transmission) buffer(length uint32) []byte {
	if cap(t.buf) < int(length) {
		t.buf = make([]byte, length)
	}
	return t.buf[:length]
}

// validFlags reports whether req carries only flags this server knows.
func validFlags(req request) bool {
	return req.flags&^cmdFlagFUA == 0
}

func (t *transmission) read(req request) (commandResult, error) {
	if !validFlags(req) || req.length > maxPayload || !t.vol.inRange(req.offset, req.length) {
		return commandResult{code: errInval}, nil
	}
	data := t.buffer(req.length)
	if _, err := t.vol.file.ReadAt(data, int64(req.offset)); err != nil {
		return t.failed("read", err), nil
	}
	return commandResult{data: data}, nil
}

func (t *transmission) write(req request) (commandResult, error) {
	if req.length > maxPayload {
		return commandResult{code: errInval}, t.discardPayload(req.length)
	}
	data := t.buffer(req.length)
	if _, err := io.ReadFull(t.conn, data); err != nil {
		return commandResult{}, ErrProtocol{Reason: "read write payload", Cause: err}
	}
	if !validFlags(req) {
		return commandResult{code: errInval}, nil
	}
	if !t.vol.inRange(req.offset, req.length) {
		return commandResult{code: errNoSpc}, nil
	}

	if _, err := t.vol.file.WriteAt(data, int64(req.offset)); err != nil {
		return t.failed("write", err), nil
	}
	return t.forceUnitAccess(req), nil
}

// discardPayload consumes the payload of a WRITE that is refused before it
// is read, so the next request header is read from the right place.
func (t *transmission) discardPayload(length uint32) error {
	if _, err := io.CopyN(io.Discard, t.conn, int64(length)); err != nil {
		return ErrProtocol{Reason: "discard write payload", Cause: err}
	}
	return nil
}

func (t *transmission) flush(req request) (commandResult, error) {
	if !validFlags(req) {
		return commandResult{code: errInval}, nil
	}
	if err := t.vol.file.Sync(); err != nil {
		return t.failed("flush", err), nil
	}
	return commandResult{}, nil
}

func (t *transmission) trim(req request) (commandResult, error) {
	if !validFlags(req) || !t.vol.inRange(req.offset, req.length) {
		return commandResult{code: errInval}, nil
	}
	if req.length == 0 {
		return commandResult{}, nil
	}
	if err := t.vol.trim(int64(req.offset), int64(req.length)); err != nil {
		return t.failed("trim", err), nil
	}
	return t.forceUnitAccess(req), nil
}

// forceUnitAccess syncs the volume when the request carries NBD_CMD_FLAG_FUA.
func (t *transmission) forceUnitAccess(req request) commandResult {
	if req.flags&cmdFlagFUA == 0 {
		return commandResult{}
	}
	if err := t.vol.file.Sync(); err != nil {
		return t.failed("sync", err)
	}
	return commandResult{}
}

// disconnect makes the volume durable before the session ends; the
// protocol sends no reply to NBD_CMD_DISC.
func (t *transmission) disconnect(_ request) (commandResult, error) {
	if err := t.vol.file.Sync(); err != nil {
		return commandResult{}, ErrVolume{Identity: t.identity, Op: "sync", Cause: err}
	}
	return commandResult{disconnect: true}, nil
}

func (t *transmission) unsupported(_ request) (commandResult, error) {
	return commandResult{code: errInval}, nil
}

// failed logs a volume I/O failure and answers the request with EIO.
func (t *transmission) failed(op string, err error) commandResult {
	t.logger.Warn("nbd volume i/o failed", slog.Any("error", ErrVolume{Identity: t.identity, Op: op, Cause: err}))
	return commandResult{code: errIO}
}

// close ends the session after NBD_CMD_DISC. Closing the TLS connection
// sends close_notify, so the client sees a clean end of stream.
func (t *transmission) close() error {
	if err := t.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return ErrProtocol{Reason: "close after disconnect", Cause: err}
	}
	return nil
}
