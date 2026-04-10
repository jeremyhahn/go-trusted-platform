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

package bmc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// bmcBasePath is the base path for BMC API endpoints.
const bmcBasePath = "/api/v1/bmc"

// validateBMCFlags validates that all required BMC flags are set.
func validateBMCFlags(flags *bmcFlags) error {
	if flags.serverURL == "" {
		return ErrServerURLRequired{}
	}
	if flags.profileID == "" {
		return ErrProfileIDRequired{}
	}
	return nil
}

// buildURL constructs a BMC API URL from the server URL, profile ID, and path segments.
func buildURL(serverURL, profileID string, segments ...string) string {
	base := strings.TrimRight(serverURL, "/") + bmcBasePath + "/" + profileID
	for _, seg := range segments {
		base += "/" + seg
	}
	return base
}

// doGet performs an HTTP GET request and decodes the JSON response into dest.
func doGet(ctx context.Context, client *http.Client, url string, dest interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ErrRequestBuildFailed{Cause: err}
	}

	resp, err := client.Do(req)
	if err != nil {
		return ErrRequestFailed{URL: url, Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return ErrUnexpectedStatus{StatusCode: resp.StatusCode, Body: string(body)}
	}

	if err := json.NewDecoder(resp.Body).Decode(dest); err != nil {
		return ErrResponseDecodeFailed{Cause: err}
	}

	return nil
}

// doPost performs an HTTP POST request with a JSON body and decodes the response into dest.
func doPost(ctx context.Context, client *http.Client, url string, payload interface{}, dest interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return ErrRequestEncodeFailed{Cause: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return ErrRequestBuildFailed{Cause: err}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return ErrRequestFailed{URL: url, Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return ErrUnexpectedStatus{StatusCode: resp.StatusCode, Body: string(respBody)}
	}

	if err := json.NewDecoder(resp.Body).Decode(dest); err != nil {
		return ErrResponseDecodeFailed{Cause: err}
	}

	return nil
}

// doDelete performs an HTTP DELETE request and decodes the JSON response into dest.
func doDelete(ctx context.Context, client *http.Client, url string, dest interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return ErrRequestBuildFailed{Cause: err}
	}

	resp, err := client.Do(req)
	if err != nil {
		return ErrRequestFailed{URL: url, Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return ErrUnexpectedStatus{StatusCode: resp.StatusCode, Body: string(body)}
	}

	if err := json.NewDecoder(resp.Body).Decode(dest); err != nil {
		return ErrResponseDecodeFailed{Cause: err}
	}

	return nil
}

// validPowerActions is the set of valid power action strings.
var validPowerActions = map[string]PowerAction{
	"on":    PowerActionOn,
	"off":   PowerActionOff,
	"reset": PowerActionReset,
	"cycle": PowerActionCycle,
}

// validBootDevices is the set of valid boot device strings.
var validBootDevices = map[string]bool{
	"pxe":   true,
	"disk":  true,
	"cdrom": true,
	"bios":  true,
}
