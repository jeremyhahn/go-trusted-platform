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

package provision

// provisionFlags holds the common flags for provisioning commands.
type provisionFlags struct {
	serverURL string
	ekSerial  string
	mac       string
	eabKID    string
	eabHMAC   string
	output    string
	timeout   int
}

// nonceResponse is the server response for the nonce endpoint.
type nonceResponse struct {
	Nonce string `json:"nonce"`
}

// configRequest is the request body sent to the provisioning config endpoint.
// JSON field names must match the server-side ConfigRequest in
// pkg/provisioning/configdelivery/types.go.
type configRequest struct {
	EKSerial   string `json:"ek_serial,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
	EABKeyID   string `json:"eab_key_id"`
	EABHMAC    string `json:"eab_hmac"`
	Nonce      string `json:"nonce"`
}

// configResponse is the server response for the config endpoint.
type configResponse struct {
	Status       string `json:"status"`
	Config       string `json:"config,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	ProvisionURL string `json:"provision_url,omitempty"`
}

// pollResponse is the server response for the poll endpoint.
type pollResponse struct {
	Status string `json:"status"`
	Config string `json:"config,omitempty"`
}

// provisionStatus constants define the possible provisioning response statuses.
const (
	statusOK      = "ok"
	statusPending = "pending"
)
