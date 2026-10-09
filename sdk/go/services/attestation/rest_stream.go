// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package attestation

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// verdictStreamPath is the REST route of the device verdict stream, relative
// to the API base URL.
const verdictStreamPath = "/attestation/verdicts/stream"

// RESTStreamConfig configures a REST device verdict stream.
type RESTStreamConfig struct {
	// BaseURL is the API base URL, for example "https://host:8443/api/v1".
	BaseURL string
	// HTTPClient carries the request. It must not set a Timeout: the stream
	// lasts until ctx ends. Nil uses http.DefaultClient.
	HTTPClient *http.Client
	// AuthToken is the bearer token. Empty sends none, for a client whose
	// HTTPClient authenticates by its TLS certificate.
	AuthToken string
}

// RESTDeviceVerdictStream receives device verdicts over Server-Sent Events. It
// satisfies DeviceVerdictStream.
type RESTDeviceVerdictStream struct {
	body   io.Closer
	reader *bufio.Reader
}

// Recv returns the next verdict. It returns io.EOF when the server closed the
// stream cleanly, *ErrVerdictStreamEnded when the server ended it and the
// caller must follow again, and the read error when the connection broke or ctx
// ended.
func (s *RESTDeviceVerdictStream) Recv() (*platformv1.DeviceVerdictEvent, error) {
	var event, data string
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			if event == "" {
				continue
			}
			return decodeVerdictEvent(event, data)
		case strings.HasPrefix(line, ":"):
			// A comment: the server's subscription notice or heartbeat.
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data = strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
		}
	}
}

// Close ends the stream and releases its connection.
func (s *RESTDeviceVerdictStream) Close() error {
	return s.body.Close()
}

func decodeVerdictEvent(event, data string) (*platformv1.DeviceVerdictEvent, error) {
	switch event {
	case "verdict":
		verdict := &platformv1.DeviceVerdictEvent{}
		if err := protojson.Unmarshal([]byte(data), verdict); err != nil {
			return nil, &ErrDecodeDeviceVerdictFailed{Cause: err}
		}
		return verdict, nil
	case "error":
		reason, err := strconv.Unquote(data)
		if err != nil {
			reason = data
		}
		return nil, &ErrVerdictStreamEnded{Reason: reason}
	}
	return nil, &ErrDecodeDeviceVerdictFailed{Cause: &ErrUnknownStreamEvent{Event: event}}
}

// StreamDeviceVerdictsREST follows every device verdict platformd records from
// now on, over the REST Server-Sent Events route, until ctx ends. It carries
// the same events, with the same audience rules, as Client.StreamDeviceVerdicts
// on gRPC. The caller closes the returned stream.
func StreamDeviceVerdictsREST(ctx context.Context, cfg RESTStreamConfig) (*RESTDeviceVerdictStream, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cfg.BaseURL, "/")+verdictStreamPath, nil)
	if err != nil {
		return nil, &ErrStreamDeviceVerdictsFailed{Cause: err}
	}
	req.Header.Set("Accept", "text/event-stream")
	if cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.AuthToken)
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, &ErrStreamDeviceVerdictsFailed{Cause: err}
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			body = nil
		}
		return nil, &ErrStreamDeviceVerdictsFailed{
			Cause: &ErrVerdictStreamRefused{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body))},
		}
	}
	return &RESTDeviceVerdictStream{body: resp.Body, reader: bufio.NewReader(resp.Body)}, nil
}
