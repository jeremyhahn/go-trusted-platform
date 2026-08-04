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

package compute

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/digitalocean/go-qemu/qmp"
)

// followPollInterval is how often the serial transcript is polled for growth
// during a follow.
var followPollInterval = 200 * time.Millisecond

// subscribeVMLifecycleEvents subscribes to the instance's QMP events and
// invokes emit for each. It is a seam so tests can feed synthetic lifecycle
// events without a real VM.
var subscribeVMLifecycleEvents = defaultSubscribeVMLifecycleEvents

// serialLogPath returns the on-disk serial transcript path for an instance.
// It must match the SerialLogFile configured on the QEMU VM at boot.
func serialLogPath(inst *qemuInstance) string {
	if inst == nil || inst.instance == nil || inst.instance.Config == nil {
		return ""
	}
	return filepath.Join(inst.instance.Config.WorkDir, "serial.log")
}

// StreamVMLogs streams a VM's serial transcript and (when following) QMP
// lifecycle events. Guest-application logs are out of scope: surfacing them
// would require an in-guest agent (QGA) which the platform does not deploy.
//
// The backlog is the serial transcript (optionally limited to the last
// opts.TailLines lines). When opts.Follow is set the method then tails the
// transcript for new lines and surfaces QMP lifecycle events (start/stop/
// shutdown/reset) as synthetic entries, until the context is canceled or sink
// returns an error. Serial lines carry no embedded timestamp and are stamped at
// read time, so opts.Since is only meaningful for entries observed live.
func (o *QEMUOrchestrator) StreamVMLogs(ctx context.Context, instanceID string, opts VMLogOptions, sink VMLogSink) error {
	if instanceID == "" {
		return ErrInvalidInstanceID
	}
	if sink == nil {
		return &MessageError{Msg: "log sink is required"}
	}

	o.mu.RLock()
	inst, exists := o.instances[instanceID]
	o.mu.RUnlock()
	if !exists {
		return ErrInstanceNotFound
	}

	path := serialLogPath(inst)
	if path == "" {
		return &SentinelCauseError{Sentinel: ErrVMLogsUnavailable, Cause: &MessageError{Msg: "instance has no work directory"}}
	}

	backlog, offset, err := readSerialBacklog(path, opts.TailLines)
	if err != nil {
		if os.IsNotExist(err) && !opts.Follow {
			return &SentinelCauseError{Sentinel: ErrVMLogsUnavailable, Cause: &MessageError{Msg: "serial transcript not found"}}
		}
		if !os.IsNotExist(err) {
			return &WrappedError{Msg: "failed to read serial transcript", Err: err}
		}
		// Following a not-yet-created transcript: start from offset 0.
		offset = 0
	}

	for _, line := range backlog {
		entry := serialEntry(line)
		if !opts.Since.IsZero() && entry.Timestamp.Before(opts.Since) {
			continue
		}
		if serr := sink(entry); serr != nil {
			return serr
		}
	}

	if !opts.Follow {
		return nil
	}

	return o.followVMLogs(ctx, inst, path, offset, sink)
}

// followVMLogs tails the serial transcript and multiplexes QMP lifecycle
// events onto the single sink goroutine. All sink calls happen here so the
// sink need not be concurrency-safe.
func (o *QEMUOrchestrator) followVMLogs(ctx context.Context, inst *qemuInstance, path string, offset int64, sink VMLogSink) error {
	eventCh := make(chan LogEntry, 64)
	// QMP lifecycle events are best-effort; a subscription failure must not
	// abort the serial tail.
	if err := subscribeVMLifecycleEvents(ctx, o, inst, func(e LogEntry) {
		select {
		case eventCh <- e:
		case <-ctx.Done():
		}
	}); err != nil {
		o.logger.Warnf("VM logs: QMP event subscription unavailable for %s: %v", inst.instance.ID, err)
	}

	tail := &serialTailer{path: path, offset: offset}
	ticker := time.NewTicker(followPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case e := <-eventCh:
			if err := sink(e); err != nil {
				return err
			}
		case <-ticker.C:
			lines, err := tail.poll()
			if err != nil {
				o.logger.Warnf("VM logs: serial tail error for %s: %v", inst.instance.ID, err)
				continue
			}
			for _, line := range lines {
				if err := sink(serialEntry(line)); err != nil {
					return err
				}
			}
		}
	}
}

// serialEntry wraps a serial transcript line as a LogEntry stamped now.
func serialEntry(line string) LogEntry {
	return LogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   line,
		Source:    "serial",
	}
}

// readSerialBacklog reads the serial transcript and returns its lines (limited
// to the last tailLines when tailLines > 0) together with the byte offset at
// end-of-file for subsequent tailing.
func readSerialBacklog(path string, tailLines int) ([]string, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	offset := int64(len(data))
	lines := splitLines(data)
	if tailLines > 0 && len(lines) > tailLines {
		lines = lines[len(lines)-tailLines:]
	}
	return lines, offset, nil
}

// splitLines splits a byte buffer into newline-terminated lines, dropping a
// trailing empty fragment.
func splitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	raw := bytes.Split(data, []byte{'\n'})
	// A trailing '\n' yields a final empty element; drop it.
	if len(raw) > 0 && len(raw[len(raw)-1]) == 0 {
		raw = raw[:len(raw)-1]
	}
	lines := make([]string, 0, len(raw))
	for _, r := range raw {
		lines = append(lines, string(bytes.TrimRight(r, "\r")))
	}
	return lines
}

// serialTailer reads newly appended complete lines from a growing file across
// successive polls, buffering any partial trailing line until it is completed.
type serialTailer struct {
	path    string
	offset  int64
	partial []byte
}

// poll reads bytes appended since the last poll and returns any complete lines.
func (t *serialTailer) poll() ([]string, error) {
	f, err := os.Open(t.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	if _, err := f.Seek(t.offset, io.SeekStart); err != nil {
		return nil, err
	}

	appended, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if len(appended) == 0 {
		return nil, nil
	}
	t.offset += int64(len(appended))

	buf := append(t.partial, appended...)
	var lines []string
	for {
		idx := bytes.IndexByte(buf, '\n')
		if idx < 0 {
			break
		}
		lines = append(lines, string(bytes.TrimRight(buf[:idx], "\r")))
		buf = buf[idx+1:]
	}
	t.partial = append(t.partial[:0], buf...)
	return lines, nil
}

// defaultSubscribeVMLifecycleEvents connects the instance's QMP monitor and
// forwards lifecycle events as synthetic log entries.
func defaultSubscribeVMLifecycleEvents(ctx context.Context, o *QEMUOrchestrator, inst *qemuInstance, emit func(LogEntry)) error {
	mon := inst.vm.Monitor()
	if mon == nil || !mon.IsConnected() {
		if err := inst.vm.ConnectMonitor(ctx); err != nil {
			return &WrappedError{Msg: "failed to connect QMP monitor", Err: err}
		}
		mon = inst.vm.Monitor()
	}
	return mon.SubscribeEvents(ctx, func(ev qmp.Event) {
		emit(LogEntry{
			Timestamp: time.Now(),
			Level:     "EVENT",
			Message:   "qmp event: " + ev.Event,
			Source:    "qmp",
		})
	})
}
