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

package switchsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const basePath = "/api/v1/switches"

// Client provides access to physical switch management operations via REST.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient creates a new switch SDK client.
func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {
	if httpClient == nil {
		return nil, ErrNilHTTPClient{}
	}
	if baseURL == "" {
		return nil, ErrEmptyBaseURL{}
	}
	return &Client{
		httpClient: httpClient,
		baseURL:    strings.TrimRight(baseURL, "/"),
	}, nil
}

// ListPorts returns the status of all physical ports on the named switch.
func (c *Client) ListPorts(ctx context.Context, switchName string) ([]*switchmgmt.PortStatus, error) {
	endpoint := c.baseURL + basePath + "/" + url.PathEscape(switchName) + "/ports"

	var ports []*switchmgmt.PortStatus
	if err := c.doGet(ctx, endpoint, &ports); err != nil {
		return nil, ErrListPortsFailed{Switch: switchName, Cause: err}
	}
	return ports, nil
}

// GetPortStatus returns the full observable state of a single port.
func (c *Client) GetPortStatus(ctx context.Context, switchName, port string) (*switchmgmt.PortStatus, error) {
	endpoint := c.baseURL + basePath + "/" + url.PathEscape(switchName) +
		"/ports/" + url.PathEscape(port)

	var status switchmgmt.PortStatus
	if err := c.doGet(ctx, endpoint, &status); err != nil {
		return nil, ErrGetPortStatusFailed{Switch: switchName, Port: port, Cause: err}
	}
	return &status, nil
}

// SetPortVLAN moves an access-mode port to the specified VLAN.
func (c *Client) SetPortVLAN(ctx context.Context, switchName, port string, vlanID uint16) error {
	endpoint := c.baseURL + basePath + "/" + url.PathEscape(switchName) +
		"/ports/" + url.PathEscape(port) + "/vlan"

	body := map[string]uint16{"vlan_id": vlanID}
	if err := c.doPost(ctx, endpoint, body); err != nil {
		return ErrSetPortVLANFailed{Switch: switchName, Port: port, VLANID: vlanID, Cause: err}
	}
	return nil
}

// EnablePort administratively enables a port.
func (c *Client) EnablePort(ctx context.Context, switchName, port string) error {
	endpoint := c.baseURL + basePath + "/" + url.PathEscape(switchName) +
		"/ports/" + url.PathEscape(port) + "/enable"

	if err := c.doPost(ctx, endpoint, nil); err != nil {
		return ErrEnablePortFailed{Switch: switchName, Port: port, Cause: err}
	}
	return nil
}

// DisablePort administratively shuts down a port.
func (c *Client) DisablePort(ctx context.Context, switchName, port string) error {
	endpoint := c.baseURL + basePath + "/" + url.PathEscape(switchName) +
		"/ports/" + url.PathEscape(port) + "/disable"

	if err := c.doPost(ctx, endpoint, nil); err != nil {
		return ErrDisablePortFailed{Switch: switchName, Port: port, Cause: err}
	}
	return nil
}

// doGet performs an HTTP GET and decodes the response payload into dst.
func (c *Client) doGet(ctx context.Context, endpoint string, dst interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ErrRequestBuildFailed{Cause: err}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ErrRequestFailed{Method: http.MethodGet, URL: endpoint, Cause: err}
	}
	defer resp.Body.Close()

	return c.decodeResponse(resp, dst)
}

// doPost performs an HTTP POST with an optional JSON body.
func (c *Client) doPost(ctx context.Context, endpoint string, body interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return ErrRequestEncodeFailed{Cause: err}
		}
		bodyReader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bodyReader)
	if err != nil {
		return ErrRequestBuildFailed{Cause: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ErrRequestFailed{Method: http.MethodPost, URL: endpoint, Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return ErrUnexpectedStatus{StatusCode: resp.StatusCode, Body: string(respBody)}
	}

	return nil
}

// decodeResponse reads the HTTP response body and extracts the payload from the
// standard WebServiceResponse envelope.
func (c *Client) decodeResponse(resp *http.Response, dst interface{}) error {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return ErrUnexpectedStatus{StatusCode: resp.StatusCode, Body: string(respBody)}
	}

	// The REST API wraps all responses in a WebServiceResponse envelope.
	var envelope response.WebServiceResponse
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return ErrResponseDecodeFailed{Cause: err}
	}

	if !envelope.Success {
		return ErrUnexpectedStatus{StatusCode: resp.StatusCode, Body: envelope.Error}
	}

	// Re-marshal the payload and decode into the destination type.
	payloadBytes, err := json.Marshal(envelope.Payload)
	if err != nil {
		return ErrResponseDecodeFailed{Cause: err}
	}

	if err := json.Unmarshal(payloadBytes, dst); err != nil {
		return ErrResponseDecodeFailed{Cause: err}
	}

	return nil
}
