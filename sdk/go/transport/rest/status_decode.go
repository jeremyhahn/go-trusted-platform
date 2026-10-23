package rest

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// ErrUnknownSystemStatus reports a status string GET /api/v1/status answered
// with that names no platform.v1.SystemStatus.
type ErrUnknownSystemStatus struct {
	Status string
}

// Error implements the error interface.
func (e ErrUnknownSystemStatus) Error() string {
	return fmt.Sprintf("unknown system status %q", e.Status)
}

// ErrInvalidStatusTimestamp reports a GET /api/v1/status timestamp that is
// neither an RFC 3339 string nor a unix-seconds number.
type ErrInvalidStatusTimestamp struct {
	Raw string
}

// Error implements the error interface.
func (e ErrInvalidStatusTimestamp) Error() string {
	return fmt.Sprintf("invalid status timestamp %s", e.Raw)
}

// systemStatusByWord maps the lowercase words the daemon's status handlers
// answer with to the proto enum. The daemon writes plain JSON DTOs here, not
// protojson, so the enum arrives as "ready" rather than "SYSTEM_STATUS_READY".
var systemStatusByWord = map[string]platformv1.SystemStatus{
	"initializing":  platformv1.SystemStatus_SYSTEM_STATUS_INITIALIZING,
	"ready":         platformv1.SystemStatus_SYSTEM_STATUS_READY,
	"degraded":      platformv1.SystemStatus_SYSTEM_STATUS_DEGRADED,
	"unavailable":   platformv1.SystemStatus_SYSTEM_STATUS_UNAVAILABLE,
	"shutting_down": platformv1.SystemStatus_SYSTEM_STATUS_SHUTTING_DOWN,
}

// statusBody is the part of GET /api/v1/status that GetStatusResponse carries.
// Fields the proto has no home for (uptime, the nested system block, version
// strings) are ignored, as protojson's DiscardUnknown would.
type statusBody struct {
	Status    string          `json:"status"`
	Timestamp json.RawMessage `json:"timestamp"`
}

// decodeStatusResponse fills resp from the daemon's status DTO. The timestamp
// is an RFC 3339 string on the liveness route and unix seconds on the platform
// handler; protojson accepts neither the integer nor the lowercase status word.
func decodeStatusResponse(data []byte, resp *platformv1.GetStatusResponse) error {
	var body statusBody
	if err := json.Unmarshal(data, &body); err != nil {
		return err
	}

	if body.Status != "" {
		word := strings.ToLower(strings.TrimPrefix(strings.ToUpper(body.Status), "SYSTEM_STATUS_"))
		st, ok := systemStatusByWord[word]
		if !ok {
			return ErrUnknownSystemStatus{Status: body.Status}
		}
		resp.Status = st
	}

	if len(body.Timestamp) == 0 || string(body.Timestamp) == "null" {
		return nil
	}
	ts, err := parseStatusTimestamp(body.Timestamp)
	if err != nil {
		return err
	}
	resp.Timestamp = timestamppb.New(ts)
	return nil
}

func parseStatusTimestamp(raw json.RawMessage) (time.Time, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		ts, err := time.Parse(time.RFC3339, text)
		if err != nil {
			return time.Time{}, ErrInvalidStatusTimestamp{Raw: string(raw)}
		}
		return ts, nil
	}
	var seconds int64
	if err := json.Unmarshal(raw, &seconds); err != nil {
		return time.Time{}, ErrInvalidStatusTimestamp{Raw: string(raw)}
	}
	return time.Unix(seconds, 0).UTC(), nil
}
