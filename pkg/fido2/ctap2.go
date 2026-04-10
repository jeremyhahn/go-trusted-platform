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

package fido2

import (
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator implements FIDO2 CTAP2 protocol operations
type Authenticator struct {
	device *CTAPHIDDevice
	config *Config
	info   *DeviceInfo
}

// NewAuthenticator creates a new FIDO2 authenticator
func NewAuthenticator(device *CTAPHIDDevice, config *Config) (*Authenticator, error) {
	auth := &Authenticator{
		device: device,
		config: config,
	}

	// Get device info
	info, err := auth.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get authenticator info: %w", err)
	}
	auth.info = info

	return auth, nil
}

// GetInfo implements CTAP2 authenticatorGetInfo
func (a *Authenticator) GetInfo() (*DeviceInfo, error) {
	// Send GetInfo command (no request parameters)
	resp, err := a.device.SendCBOR(CmdGetInfo, nil)
	if err != nil {
		return nil, fmt.Errorf("GetInfo command failed: %w", err)
	}

	// Decode CBOR response
	var infoMap map[int]interface{}
	if err := cbor.Unmarshal(resp, &infoMap); err != nil {
		return nil, fmt.Errorf("failed to decode GetInfo response: %w", err)
	}

	info := &DeviceInfo{
		Options: make(map[string]bool),
	}

	// Parse response fields
	// Field 0x01: versions
	if versions, ok := infoMap[0x01].([]interface{}); ok {
		for _, v := range versions {
			if s, ok := v.(string); ok {
				info.Versions = append(info.Versions, s)
			}
		}
	}

	// Field 0x02: extensions
	if extensions, ok := infoMap[0x02].([]interface{}); ok {
		for _, ext := range extensions {
			if s, ok := ext.(string); ok {
				info.Extensions = append(info.Extensions, s)
			}
		}
	}

	// Field 0x03: AAGUID
	if aaguid, ok := infoMap[0x03].([]byte); ok {
		info.AAGUID = aaguid
	}

	// Field 0x04: options
	if options, ok := infoMap[0x04].(map[interface{}]interface{}); ok {
		for k, v := range options {
			if key, ok := k.(string); ok {
				if val, ok := v.(bool); ok {
					info.Options[key] = val
				}
			}
		}
	}

	// Field 0x05: maxMsgSize
	if maxMsgSize, ok := infoMap[0x05].(uint64); ok {
		info.MaxMsgSize = maxMsgSize
	}

	// Field 0x06: pinProtocols
	if pinProtos, ok := infoMap[0x06].([]interface{}); ok {
		for _, p := range pinProtos {
			if proto, ok := p.(uint64); ok {
				info.PINProtocols = append(info.PINProtocols, proto)
			}
		}
	}

	// Field 0x07: maxCredentialCountInList
	if maxCreds, ok := infoMap[0x07].(uint64); ok {
		info.MaxCredentialCount = maxCreds
	}

	// Field 0x08: maxCredentialIdLength
	if maxCredIDLen, ok := infoMap[0x08].(uint64); ok {
		info.MaxCredentialIDLen = maxCredIDLen
	}

	// Field 0x09: transports
	if transports, ok := infoMap[0x09].([]interface{}); ok {
		for _, t := range transports {
			if s, ok := t.(string); ok {
				info.Transports = append(info.Transports, s)
			}
		}
	}

	// Field 0x0A: algorithms
	if algos, ok := infoMap[0x0A].([]interface{}); ok {
		for _, alg := range algos {
			if algMap, ok := alg.(map[interface{}]interface{}); ok {
				param := PublicKeyCredentialParameter{}
				if algType, ok := algMap["type"].(string); ok {
					param.Type = algType
				}
				if algID, ok := algMap["alg"].(int64); ok {
					param.Alg = int(algID)
				}
				info.Algorithms = append(info.Algorithms, param)
			}
		}
	}

	return info, nil
}

// MakeCredential implements CTAP2 authenticatorMakeCredential
func (a *Authenticator) MakeCredential(req *MakeCredentialRequest) (*MakeCredentialResponse, error) {
	// Build CBOR request
	reqMap := make(map[int]interface{})

	// 0x01: clientDataHash (required)
	reqMap[0x01] = req.ClientDataHash

	// 0x02: rp (required)
	rpMap := map[string]interface{}{
		"id":   req.RP.ID,
		"name": req.RP.Name,
	}
	if req.RP.Icon != "" {
		rpMap["icon"] = req.RP.Icon
	}
	reqMap[0x02] = rpMap

	// 0x03: user (required)
	userMap := map[string]interface{}{
		"id":          req.User.ID,
		"name":        req.User.Name,
		"displayName": req.User.DisplayName,
	}
	if req.User.Icon != "" {
		userMap["icon"] = req.User.Icon
	}
	reqMap[0x03] = userMap

	// 0x04: pubKeyCredParams (required)
	var pubKeyParams []interface{}
	for _, param := range req.PubKeyCredParams {
		pubKeyParams = append(pubKeyParams, map[string]interface{}{
			"type": param.Type,
			"alg":  param.Alg,
		})
	}
	reqMap[0x04] = pubKeyParams

	// 0x05: excludeList (optional)
	if len(req.ExcludeList) > 0 {
		var excludeList []interface{}
		for _, cred := range req.ExcludeList {
			credMap := map[string]interface{}{
				"type": cred.Type,
				"id":   cred.ID,
			}
			if len(cred.Transports) > 0 {
				credMap["transports"] = cred.Transports
			}
			excludeList = append(excludeList, credMap)
		}
		reqMap[0x05] = excludeList
	}

	// 0x06: extensions (optional)
	if len(req.Extensions) > 0 {
		reqMap[0x06] = req.Extensions
	}

	// 0x07: options (optional)
	optionsMap := make(map[string]bool)
	if req.Options.RK {
		optionsMap["rk"] = true
	}
	if req.Options.UV {
		optionsMap["uv"] = true
	}
	if len(optionsMap) > 0 {
		reqMap[0x07] = optionsMap
	}

	// 0x08: pinUVAuthParam (optional)
	if len(req.PinUVAuthParam) > 0 {
		reqMap[0x08] = req.PinUVAuthParam
	}

	// 0x09: pinUVAuthProtocol (optional)
	if req.PinUVAuthProtocol > 0 {
		reqMap[0x09] = req.PinUVAuthProtocol
	}

	// Send command
	resp, err := a.device.SendCBOR(CmdMakeCredential, reqMap)
	if err != nil {
		return nil, fmt.Errorf("MakeCredential command failed: %w", err)
	}

	// Decode response
	var respMap map[int]interface{}
	if err := cbor.Unmarshal(resp, &respMap); err != nil {
		return nil, fmt.Errorf("failed to decode MakeCredential response: %w", err)
	}

	result := &MakeCredentialResponse{
		AttStmt: make(map[string]interface{}),
	}

	// 0x01: fmt (required)
	if fmt, ok := respMap[0x01].(string); ok {
		result.Fmt = fmt
	}

	// 0x02: authData (required)
	if authData, ok := respMap[0x02].([]byte); ok {
		result.AuthData = authData
	}

	// 0x03: attStmt (required)
	if attStmt, ok := respMap[0x03].(map[interface{}]interface{}); ok {
		for k, v := range attStmt {
			if key, ok := k.(string); ok {
				result.AttStmt[key] = v
			}
		}
	}

	// 0x04: epAtt (optional)
	if epAtt, ok := respMap[0x04].(bool); ok {
		result.EPAtt = epAtt
	}

	// 0x05: largeBlobKey (optional)
	if largeBlobKey, ok := respMap[0x05].([]byte); ok {
		result.LargeBlobKey = largeBlobKey
	}

	return result, nil
}

// GetAssertion implements CTAP2 authenticatorGetAssertion
func (a *Authenticator) GetAssertion(req *GetAssertionRequest) (*GetAssertionResponse, error) {
	// Build CBOR request
	reqMap := make(map[int]interface{})

	// 0x01: rpId (required)
	reqMap[0x01] = req.RPID

	// 0x02: clientDataHash (required)
	reqMap[0x02] = req.ClientDataHash

	// 0x03: allowList (optional)
	if len(req.AllowList) > 0 {
		var allowList []interface{}
		for _, cred := range req.AllowList {
			credMap := map[string]interface{}{
				"type": cred.Type,
				"id":   cred.ID,
			}
			if len(cred.Transports) > 0 {
				credMap["transports"] = cred.Transports
			}
			allowList = append(allowList, credMap)
		}
		reqMap[0x03] = allowList
	}

	// 0x04: extensions (optional)
	if len(req.Extensions) > 0 {
		reqMap[0x04] = req.Extensions
	}

	// 0x05: options (optional)
	optionsMap := make(map[string]bool)
	if req.Options.UP {
		optionsMap["up"] = true
	}
	if req.Options.UV {
		optionsMap["uv"] = true
	}
	if len(optionsMap) > 0 {
		reqMap[0x05] = optionsMap
	}

	// 0x06: pinUVAuthParam (optional)
	if len(req.PinUVAuthParam) > 0 {
		reqMap[0x06] = req.PinUVAuthParam
	}

	// 0x07: pinUVAuthProtocol (optional)
	if req.PinUVAuthProtocol > 0 {
		reqMap[0x07] = req.PinUVAuthProtocol
	}

	// Send command
	resp, err := a.device.SendCBOR(CmdGetAssertion, reqMap)
	if err != nil {
		return nil, fmt.Errorf("GetAssertion command failed: %w", err)
	}

	// Workaround for CanoKey CBOR truncation bug
	if a.config.WorkaroundCanoKey && len(resp) > 0 {
		// Attempt to decode, if it fails, try padding
		var testMap map[int]interface{}
		if err := cbor.Unmarshal(resp, &testMap); err != nil {
			// Pad with zeros and retry
			resp = append(resp, make([]byte, 32)...)
		}
	}

	// Decode response
	var respMap map[int]interface{}
	if err := cbor.Unmarshal(resp, &respMap); err != nil {
		return nil, fmt.Errorf("failed to decode GetAssertion response: %w", err)
	}

	result := &GetAssertionResponse{}

	// 0x01: credential (optional)
	if credMap, ok := respMap[0x01].(map[interface{}]interface{}); ok {
		cred := PublicKeyCredentialDescriptor{}
		if credType, ok := credMap["type"].(string); ok {
			cred.Type = credType
		}
		if credID, ok := credMap["id"].([]byte); ok {
			cred.ID = credID
		}
		if transports, ok := credMap["transports"].([]interface{}); ok {
			for _, t := range transports {
				if s, ok := t.(string); ok {
					cred.Transports = append(cred.Transports, s)
				}
			}
		}
		result.Credential = cred
	}

	// 0x02: authData (required)
	if authData, ok := respMap[0x02].([]byte); ok {
		result.AuthData = authData
	}

	// 0x03: signature (required)
	if signature, ok := respMap[0x03].([]byte); ok {
		result.Signature = signature
	}

	// 0x04: user (optional)
	if userMap, ok := respMap[0x04].(map[interface{}]interface{}); ok {
		user := &User{}
		if userID, ok := userMap["id"].([]byte); ok {
			user.ID = userID
		}
		if name, ok := userMap["name"].(string); ok {
			user.Name = name
		}
		if displayName, ok := userMap["displayName"].(string); ok {
			user.DisplayName = displayName
		}
		if icon, ok := userMap["icon"].(string); ok {
			user.Icon = icon
		}
		result.User = user
	}

	// 0x05: numberOfCredentials (optional)
	if numCreds, ok := respMap[0x05].(uint64); ok {
		result.NumberOfCredentials = numCreds
	}

	// 0x06: userSelected (optional)
	if userSelected, ok := respMap[0x06].(bool); ok {
		result.UserSelected = userSelected
	}

	// 0x07: largeBlobKey (optional)
	if largeBlobKey, ok := respMap[0x07].([]byte); ok {
		result.LargeBlobKey = largeBlobKey
	}

	return result, nil
}

// SupportsExtension checks if the authenticator supports an extension
func (a *Authenticator) SupportsExtension(extension string) bool {
	if a.info == nil {
		return false
	}
	for _, ext := range a.info.Extensions {
		if ext == extension {
			return true
		}
	}
	return false
}

// SupportsHMACSecret checks if hmac-secret extension is supported
func (a *Authenticator) SupportsHMACSecret() bool {
	return a.SupportsExtension(ExtensionHMACSecret)
}

// Info returns the cached device info
func (a *Authenticator) Info() *DeviceInfo {
	return a.info
}

// Close closes the authenticator device
func (a *Authenticator) Close() error {
	return a.device.Close()
}

// DeviceInfo returns information about the underlying device
func (a *Authenticator) DeviceInfo() Device {
	return a.device.Info()
}

// CreateClientDataHash creates a SHA-256 hash suitable for clientDataHash
func CreateClientDataHash(challenge []byte) []byte {
	hash := sha256.Sum256(challenge)
	return hash[:]
}

// DefaultPublicKeyCredentialParameters returns default credential parameters
func DefaultPublicKeyCredentialParameters() []PublicKeyCredentialParameter {
	return []PublicKeyCredentialParameter{
		{Type: "public-key", Alg: COSEAlgES256}, // ECDSA P-256
		{Type: "public-key", Alg: COSEAlgRS256}, // RSA 2048
		{Type: "public-key", Alg: COSEAlgEdDSA}, // EdDSA
	}
}
