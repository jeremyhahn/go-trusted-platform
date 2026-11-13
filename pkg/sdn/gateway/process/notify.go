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

package process

import (
	"bytes"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// NotifySocketEnv is the environment variable that names a child's notify
// socket, as sd_notify(3) defines it.
const NotifySocketEnv = "NOTIFY_SOCKET"

// notifyMaxDatagram bounds one notify datagram. sd_notify(3) messages are a
// few short assignments; a datagram longer than this is truncated by the
// kernel and dropped.
const notifyMaxDatagram = 4096

// NotifyMessage is one parsed sd_notify(3) datagram. Each field holds the last
// assignment of its key in the datagram.
type NotifyMessage struct {
	// Ready is READY=1: the service is serving.
	Ready bool
	// Watchdog is WATCHDOG=1: a liveness keep-alive.
	Watchdog bool
	// Stopping is STOPPING=1: the exit that follows is an orderly stop.
	Stopping bool
	// Status is the STATUS= text; HasStatus tells an empty status from none.
	Status    string
	HasStatus bool
	// Errno is the ERRNO= value of a failed start; HasErrno tells it is set.
	Errno    int
	HasErrno bool
	// Unknown lists, in order, the keys the parser does not interpret.
	// sd_notify(3) receivers ignore such keys rather than refuse the datagram.
	Unknown []string
	// Pid is the sender's pid from SCM_CREDENTIALS; NotifySocket.Receive
	// sets it, ParseNotify leaves it zero.
	Pid int
}

// ParseNotify parses one sd_notify(3) datagram: newline-separated KEY=value
// assignments. Blank lines are skipped; a datagram with no assignment is
// ErrNotifyEmpty, and a line that is not a valid assignment, or a known key
// with a value the wire format does not allow, is ErrNotifyMalformed.
func ParseNotify(datagram []byte) (NotifyMessage, error) {
	var m NotifyMessage
	assignments := 0
	for raw := range bytes.SplitSeq(datagram, []byte{'\n'}) {
		if len(raw) == 0 {
			continue
		}
		line := string(raw)
		if bytes.IndexByte(raw, 0) >= 0 {
			return NotifyMessage{}, &ErrNotifyMalformed{Line: line, Reason: "contains a NUL byte"}
		}
		eq := bytes.IndexByte(raw, '=')
		if eq < 0 {
			return NotifyMessage{}, &ErrNotifyMalformed{Line: line, Reason: "no '='"}
		}
		key, value := line[:eq], line[eq+1:]
		if !validNotifyKey(key) {
			return NotifyMessage{}, &ErrNotifyMalformed{Line: line, Reason: "key is not [A-Z0-9_]+"}
		}
		switch key {
		case "READY":
			if value != "1" {
				return NotifyMessage{}, &ErrNotifyMalformed{Line: line, Reason: "READY must be 1"}
			}
			m.Ready = true
		case "WATCHDOG":
			if value != "1" {
				return NotifyMessage{}, &ErrNotifyMalformed{Line: line, Reason: "WATCHDOG must be 1"}
			}
			m.Watchdog = true
		case "STOPPING":
			if value != "1" {
				return NotifyMessage{}, &ErrNotifyMalformed{Line: line, Reason: "STOPPING must be 1"}
			}
			m.Stopping = true
		case "STATUS":
			m.Status, m.HasStatus = value, true
		case "ERRNO":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || value[0] == '+' {
				return NotifyMessage{}, &ErrNotifyMalformed{Line: line, Reason: "ERRNO must be a non-negative decimal"}
			}
			m.Errno, m.HasErrno = n, true
		default:
			m.Unknown = append(m.Unknown, key)
		}
		assignments++
	}
	if assignments == 0 {
		return NotifyMessage{}, &ErrNotifyEmpty{}
	}
	return m, nil
}

// validNotifyKey reports whether key is a non-empty run of upper-case
// letters, digits and underscores, the environment-style keys sd_notify(3)
// uses.
func validNotifyKey(key string) bool {
	if key == "" {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// NotifySocket is the supervisor's end of one child's NOTIFY_SOCKET: an
// AF_UNIX SOCK_DGRAM socket with SO_PASSCRED set, so the kernel stamps each
// datagram with its sender's SCM_CREDENTIALS. Receive accepts a datagram only
// when that pid is the expected child's; any other is dropped and counted.
type NotifySocket struct {
	path    string
	conn    *net.UnixConn
	pid     atomic.Int64
	dropped atomic.Uint64
}

// ListenNotify binds a notify socket at path that accepts datagrams from pid.
// A pid of zero accepts nothing until SetPid names the child, which lets the
// supervisor create the socket before it starts the child. The path must not
// exist.
func ListenNotify(path string, pid int) (*NotifySocket, error) {
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return nil, &ErrNotifySocket{Path: path, Op: "bind", Cause: err}
	}
	s := &NotifySocket{path: path, conn: conn}
	if err := s.setPassCred(); err != nil {
		_ = conn.Close()
		_ = os.Remove(path)
		return nil, &ErrNotifySocket{Path: path, Op: "setsockopt SO_PASSCRED", Cause: err}
	}
	s.SetPid(pid)
	return s, nil
}

func (s *NotifySocket) setPassCred() error {
	raw, err := s.conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
	}); err != nil {
		return err
	}
	return sockErr
}

// Path is the socket's file system path, the value of the child's
// NOTIFY_SOCKET.
func (s *NotifySocket) Path() string { return s.path }

// SetPid names the child whose datagrams are accepted. Credentials are
// stamped at send time, so a datagram the child queued before SetPid is
// still checked against its own pid.
func (s *NotifySocket) SetPid(pid int) { s.pid.Store(int64(pid)) }

// Dropped counts the datagrams Receive has dropped: a sender other than the
// expected child, no credentials, or a truncated datagram.
func (s *NotifySocket) Dropped() uint64 { return s.dropped.Load() }

// Receive returns the next datagram from the expected child, parsed, with its
// Pid set. Datagrams from any other sender are dropped. A deadline that
// passes first is an ErrNotifySocket wrapping os.ErrDeadlineExceeded; a zero
// deadline waits without limit. A datagram from the child that does not
// parse is returned as the parser's error.
func (s *NotifySocket) Receive(deadline time.Time) (NotifyMessage, error) {
	if err := s.conn.SetReadDeadline(deadline); err != nil {
		return NotifyMessage{}, &ErrNotifySocket{Path: s.path, Op: "set deadline", Cause: err}
	}
	buf := make([]byte, notifyMaxDatagram)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	for {
		n, oobn, flags, _, err := s.conn.ReadMsgUnix(buf, oob)
		if err != nil {
			return NotifyMessage{}, &ErrNotifySocket{Path: s.path, Op: "receive", Cause: err}
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			s.dropped.Add(1)
			continue
		}
		pid, ok := credentialsPid(oob[:oobn])
		want := s.pid.Load()
		if !ok || want <= 0 || int64(pid) != want {
			s.dropped.Add(1)
			continue
		}
		m, err := ParseNotify(buf[:n])
		if err != nil {
			return NotifyMessage{}, err
		}
		m.Pid = int(pid)
		return m, nil
	}
}

// credentialsPid returns the pid of the SCM_CREDENTIALS message in oob.
func credentialsPid(oob []byte) (int32, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, false
	}
	for i := range msgs {
		if msgs[i].Header.Level != unix.SOL_SOCKET || msgs[i].Header.Type != unix.SCM_CREDENTIALS {
			continue
		}
		cred, err := unix.ParseUnixCredentials(&msgs[i])
		if err != nil {
			return 0, false
		}
		return cred.Pid, true
	}
	return 0, false
}

// Close closes the socket and removes its path.
func (s *NotifySocket) Close() error {
	err := s.conn.Close()
	if rmErr := os.Remove(s.path); rmErr != nil && !os.IsNotExist(rmErr) && err == nil {
		err = rmErr
	}
	if err != nil {
		return &ErrNotifySocket{Path: s.path, Op: "close", Cause: err}
	}
	return nil
}

// Notify sends state, newline-separated sd_notify(3) assignments such as
// "READY=1", to the socket NOTIFY_SOCKET names. It is the child's side of the
// supervisor's notify socket. With NOTIFY_SOCKET unset or empty it does
// nothing and returns nil, so a service run outside platformd needs no
// special case. A leading '@' names an abstract socket.
func Notify(state string) error {
	path := os.Getenv(NotifySocketEnv)
	if path == "" {
		return nil
	}
	if state == "" {
		return &ErrNotifySend{Socket: path, Cause: &ErrNotifyEmpty{}}
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return &ErrNotifySend{Socket: path, Cause: err}
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(state)); err != nil {
		return &ErrNotifySend{Socket: path, Cause: err}
	}
	return nil
}
