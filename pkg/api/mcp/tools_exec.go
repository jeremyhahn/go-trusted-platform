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

package mcp

import (
	"context"
	"encoding/base64"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// vTPM tool execution handlers

func (r *ToolRegistry) executeVTPMCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	algorithm := getString(args, "algorithm")
	if algorithm == "" {
		algorithm = "RSA"
	}

	result, err := r.service.VTPMCreate(ctx, name, algorithm)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeVTPMDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	if err := r.service.VTPMDelete(ctx, name); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeVTPMList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	instances, err := r.service.VTPMList(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"instances": instances}, nil
}

func (r *ToolRegistry) executeVTPMStart(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	if err := r.service.VTPMStart(ctx, name); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeVTPMStop(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	if err := r.service.VTPMStop(ctx, name); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeVTPMQuote(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	nonceB64 := getString(args, "nonce")
	pcrs := getIntSlice(args, "pcrs")

	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, &mcpwire.WrappedError{Msg: "invalid nonce encoding", Err: err}
	}

	quote, err := r.service.VTPMQuote(ctx, name, nonce, pcrs)
	if err != nil {
		return nil, err
	}
	return marshalResult(quote)
}

func (r *ToolRegistry) executeVTPMSeal(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	dataB64 := getString(args, "data")
	pcrs := getIntSlice(args, "pcrs")

	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, &mcpwire.WrappedError{Msg: "invalid data encoding", Err: err}
	}

	sealed, err := r.service.VTPMSeal(ctx, name, data, pcrs)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"sealed": base64.StdEncoding.EncodeToString(sealed),
	}, nil
}

func (r *ToolRegistry) executeVTPMUnseal(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	sealedB64 := getString(args, "sealed")

	sealed, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		return nil, &mcpwire.WrappedError{Msg: "invalid sealed data encoding", Err: err}
	}

	data, err := r.service.VTPMUnseal(ctx, name, sealed)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"data": base64.StdEncoding.EncodeToString(data),
	}, nil
}

func (r *ToolRegistry) executeVTPMExtendPCR(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	pcr := getInt(args, "pcr")
	dataB64 := getString(args, "data")

	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, &mcpwire.WrappedError{Msg: "invalid data encoding", Err: err}
	}

	if err := r.service.VTPMExtendPCR(ctx, name, pcr, data); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeVTPMReadPCR(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	pcr := getInt(args, "pcr")

	value, err := r.service.VTPMReadPCR(ctx, name, pcr)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"value": base64.StdEncoding.EncodeToString(value),
	}, nil
}

// DNS tool execution handlers

func (r *ToolRegistry) executeDNSAddRecord(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	recordType := getString(args, "record_type")
	value := getString(args, "value")
	ttl := getInt(args, "ttl")
	if ttl == 0 {
		ttl = 300
	}

	if err := r.service.DNSAddRecord(ctx, name, recordType, value, ttl); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeDNSDeleteRecord(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	recordType := getString(args, "record_type")

	if err := r.service.DNSDeleteRecord(ctx, name, recordType); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeDNSGetRecord(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	recordType := getString(args, "record_type")

	record, err := r.service.DNSGetRecord(ctx, name, recordType)
	if err != nil {
		return nil, err
	}
	return marshalResult(record)
}

func (r *ToolRegistry) executeDNSListRecords(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	zone := getString(args, "zone")

	records, err := r.service.DNSListRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"records": records}, nil
}

func (r *ToolRegistry) executeDNSResolve(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	recordType := getString(args, "record_type")
	if recordType == "" {
		recordType = "A"
	}

	results, err := r.service.DNSResolve(ctx, name, recordType)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"results": results}, nil
}

func (r *ToolRegistry) executeDNSCreateZone(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	zone := getString(args, "zone")

	if err := r.service.DNSCreateZone(ctx, zone); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeDNSDeleteZone(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	zone := getString(args, "zone")

	if err := r.service.DNSDeleteZone(ctx, zone); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeDNSListZones(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	zones, err := r.service.DNSListZones(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"zones": zones}, nil
}

// Device tool execution handlers

func (r *ToolRegistry) executeDeviceRegister(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	deviceType := getString(args, "device_type")
	publicKeyB64 := getString(args, "public_key")

	publicKey, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, &mcpwire.WrappedError{Msg: "invalid public key encoding", Err: err}
	}

	device, err := r.service.DeviceRegister(ctx, name, deviceType, publicKey)
	if err != nil {
		return nil, err
	}
	return marshalResult(device)
}

func (r *ToolRegistry) executeDeviceGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	deviceID := getString(args, "device_id")

	device, err := r.service.DeviceGet(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	return marshalResult(device)
}

func (r *ToolRegistry) executeDeviceList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	filter := getStringMap(args, "filter")
	if filter == nil {
		filter = make(map[string]string)
	}
	if deviceType := getString(args, "device_type"); deviceType != "" {
		filter["device_type"] = deviceType
	}
	if status := getString(args, "status"); status != "" {
		filter["status"] = status
	}

	devices, err := r.service.DeviceList(ctx, filter)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"devices": devices}, nil
}

func (r *ToolRegistry) executeDeviceDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	deviceID := getString(args, "device_id")

	if err := r.service.DeviceDelete(ctx, deviceID); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeDeviceUpdate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	deviceID := getString(args, "device_id")
	updates := getMap(args, "updates")

	if err := r.service.DeviceUpdate(ctx, deviceID, updates); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeDeviceAttest(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	deviceID := getString(args, "device_id")
	evidenceB64 := getString(args, "evidence")

	evidence, err := base64.StdEncoding.DecodeString(evidenceB64)
	if err != nil {
		return nil, &mcpwire.WrappedError{Msg: "invalid evidence encoding", Err: err}
	}

	result, err := r.service.DeviceAttest(ctx, deviceID, evidence)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeDeviceRecordAttestCert(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	deviceID := getString(args, "device_id")
	if deviceID == "" {
		return nil, ErrDeviceIDRequired
	}
	reissue := getBool(args, "reissue")
	clearOnRefusal := getBool(args, "clear_on_refusal")

	result, err := r.service.DeviceRecordAttestCert(ctx, deviceID, reissue, clearOnRefusal)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeDeviceBootCertificate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	signature, err := base64.StdEncoding.DecodeString(getString(args, "signature"))
	if err != nil {
		return nil, &mcpwire.WrappedError{Msg: "invalid signature encoding", Err: err}
	}

	result, err := r.service.DeviceBootCertificate(ctx, getString(args, "identity"), signature)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeDeviceBootDelivery(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	evidence, err := base64.StdEncoding.DecodeString(getString(args, "evidence"))
	if err != nil {
		return nil, &mcpwire.WrappedError{Msg: "invalid evidence encoding", Err: err}
	}

	result, err := r.service.DeviceBootDelivery(ctx, evidence)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeDeviceProvision(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	deviceID := getString(args, "device_id")
	profile := getString(args, "profile")

	if err := r.service.DeviceProvision(ctx, deviceID, profile); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

// SDN tool execution handlers

func (r *ToolRegistry) executeSDNGetPortState(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")
	portName := getString(args, "port_name")

	state, err := r.service.SDNGetPortState(ctx, bridgeName, portName)
	if err != nil {
		return nil, err
	}
	return marshalResult(state)
}

func (r *ToolRegistry) executeSDNSetPortState(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")
	portName := getString(args, "port_name")
	state := getString(args, "state")

	if err := r.service.SDNSetPortState(ctx, bridgeName, portName, state); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeSDNListBridges(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridges, err := r.service.SDNListBridges(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"bridges": bridges}, nil
}

func (r *ToolRegistry) executeSDNCreateBridge(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")

	if err := r.service.SDNCreateBridge(ctx, bridgeName); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeSDNDeleteBridge(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")

	if err := r.service.SDNDeleteBridge(ctx, bridgeName); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeSDNAddPort(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")
	portName := getString(args, "port_name")
	portType := getString(args, "port_type")

	if err := r.service.SDNAddPort(ctx, bridgeName, portName, portType); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeSDNDeletePort(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")
	portName := getString(args, "port_name")

	if err := r.service.SDNDeletePort(ctx, bridgeName, portName); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeSDNApplyPolicy(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	policyID := getString(args, "policy_id")
	bridgeName := getString(args, "bridge_name")

	if err := r.service.SDNApplyPolicy(ctx, policyID, bridgeName); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeSDNGetPolicy(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	policyID := getString(args, "policy_id")

	policy, err := r.service.SDNGetPolicy(ctx, policyID)
	if err != nil {
		return nil, err
	}
	return marshalResult(policy)
}

func (r *ToolRegistry) executeSDNListPolicies(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	policies, err := r.service.SDNListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"policies": policies}, nil
}

// SDN Flow execution handlers

func (r *ToolRegistry) executeSDNAddFlow(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")
	flow := getMap(args, "flow")

	if err := r.service.SDNAddFlow(ctx, bridgeName, flow); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeSDNDeleteFlow(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")
	flowID := getString(args, "flow_id")

	if err := r.service.SDNDeleteFlow(ctx, bridgeName, flowID); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeSDNListFlows(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")

	flows, err := r.service.SDNListFlows(ctx, bridgeName)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"flows": flows}, nil
}

func (r *ToolRegistry) executeSDNFlushFlows(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")

	if err := r.service.SDNFlushFlows(ctx, bridgeName); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

// SDN VLAN execution handlers

func (r *ToolRegistry) executeSDNCreateVLAN(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")
	vlanID := getInt(args, "vlan_id")
	name := getString(args, "name")

	if err := r.service.SDNCreateVLAN(ctx, bridgeName, vlanID, name); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeSDNDeleteVLAN(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")
	vlanID := getInt(args, "vlan_id")

	if err := r.service.SDNDeleteVLAN(ctx, bridgeName, vlanID); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeSDNListVLANs(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")

	vlans, err := r.service.SDNListVLANs(ctx, bridgeName)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"vlans": vlans}, nil
}

// SDN Port authentication execution handlers

func (r *ToolRegistry) executeSDNAuthenticatePort(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")
	portName := getString(args, "port_name")
	credentials := getStringMap(args, "credentials")

	if err := r.service.SDNAuthenticatePort(ctx, bridgeName, portName, credentials); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeSDNRevokePortAuth(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")
	portName := getString(args, "port_name")

	if err := r.service.SDNRevokePortAuth(ctx, bridgeName, portName); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

// SDN Statistics execution handlers

func (r *ToolRegistry) executeSDNGetPortStats(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")
	portName := getString(args, "port_name")

	stats, err := r.service.SDNGetPortStats(ctx, bridgeName, portName)
	if err != nil {
		return nil, err
	}
	return marshalResult(stats)
}

func (r *ToolRegistry) executeSDNGetFlowStats(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	bridgeName := getString(args, "bridge_name")

	stats, err := r.service.SDNGetFlowStats(ctx, bridgeName)
	if err != nil {
		return nil, err
	}
	return marshalResult(stats)
}

// Health tool execution handlers

func (r *ToolRegistry) executeHealth(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	health, err := r.service.Health(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(health)
}

func (r *ToolRegistry) executeLiveness(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	liveness, err := r.service.Liveness(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(liveness)
}

func (r *ToolRegistry) executeReadiness(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	readiness, err := r.service.Readiness(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(readiness)
}

// CA tool execution handlers

func (r *ToolRegistry) executeCAInfo(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	info, err := r.service.CAInfo(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(info)
}

func (r *ToolRegistry) executeCAIssue(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	req := &CAIssueRequest{
		CommonName:         getString(args, "common_name"),
		Organization:       getString(args, "organization"),
		OrganizationalUnit: getString(args, "organizational_unit"),
		Country:            getString(args, "country"),
		Province:           getString(args, "province"),
		Locality:           getString(args, "locality"),
		Address:            getString(args, "address"),
		PostalCode:         getString(args, "postal_code"),
		DNSNames:           getStringSlice(args, "dns_names"),
		IPAddresses:        getStringSlice(args, "ip_addresses"),
		EmailAddresses:     getStringSlice(args, "email_addresses"),
		URIs:               getStringSlice(args, "uris"),
		ValidDays:          getInt(args, "valid_days"),
		Algorithm:          getString(args, "algorithm"),
		StoreType:          getString(args, "store_type"),
		KeyUsage:           getStringSlice(args, "key_usage"),
		ExtKeyUsage:        getStringSlice(args, "ext_key_usage"),
		IsCA:               getBool(args, "is_ca"),
		MaxPathLen:         getInt(args, "max_path_len"),
	}

	// Set defaults
	if req.ValidDays == 0 {
		req.ValidDays = 365
	}
	if req.Algorithm == "" {
		req.Algorithm = "ECDSA"
	}
	if req.StoreType == "" {
		req.StoreType = "software"
	}

	cert, err := r.service.CAIssue(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(cert)
}

func (r *ToolRegistry) executeCASignCSR(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	req := &CASignCSRRequest{
		CSRPEM:    getString(args, "csr_pem"),
		ValidDays: getInt(args, "valid_days"),
	}

	cert, err := r.service.CASignCSR(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(cert)
}

func (r *ToolRegistry) executeCAGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	serial := getString(args, "serial")
	includePEM := getBool(args, "include_pem")
	includeDER := getBool(args, "include_der")

	cert, err := r.service.CAGet(ctx, serial, includePEM, includeDER)
	if err != nil {
		return nil, err
	}
	return marshalResult(cert)
}

func (r *ToolRegistry) executeCAList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	limit := getInt(args, "limit")
	cursor := getString(args, "cursor")
	status := getString(args, "status")

	if limit == 0 {
		limit = 50
	}

	certs, err := r.service.CAList(ctx, limit, cursor, status)
	if err != nil {
		return nil, err
	}
	return marshalResult(certs)
}

func (r *ToolRegistry) executeCARevoke(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	serial := getString(args, "serial")
	reason := getInt(args, "reason")
	deleteKeys := getBool(args, "delete_keys")

	result, err := r.service.CARevoke(ctx, serial, reason, deleteKeys)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeCARenew(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	serial := getString(args, "serial")
	extendDays := getInt(args, "extend_days")
	preserveAttrs := getBool(args, "preserve_attrs")

	if extendDays == 0 {
		extendDays = 365
	}

	// Default preserve_attrs to true if not explicitly set
	if _, exists := args["preserve_attrs"]; !exists {
		preserveAttrs = true
	}

	cert, err := r.service.CARenew(ctx, serial, extendDays, preserveAttrs)
	if err != nil {
		return nil, err
	}
	return marshalResult(cert)
}

func (r *ToolRegistry) executeCAVerify(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	certificatePEM := getString(args, "certificate_pem")
	certificateDERB64 := getString(args, "certificate_der")
	checkRevoked := getBool(args, "check_revoked")

	// Default check_revoked to true if not explicitly set
	if _, exists := args["check_revoked"]; !exists {
		checkRevoked = true
	}

	// Decode DER if provided
	var certificateDER []byte
	if certificateDERB64 != "" {
		var err error
		certificateDER, err = base64.StdEncoding.DecodeString(certificateDERB64)
		if err != nil {
			return nil, &mcpwire.WrappedError{Msg: "invalid certificate_der encoding", Err: err}
		}
	}

	result, err := r.service.CAVerify(ctx, certificatePEM, certificateDER, checkRevoked)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeCACRL(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	crl, err := r.service.CACRL(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(crl)
}

func (r *ToolRegistry) executeCABundle(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	storeType := getString(args, "store_type")
	algorithm := getString(args, "algorithm")

	bundle, err := r.service.CABundle(ctx, storeType, algorithm)
	if err != nil {
		return nil, err
	}
	return marshalResult(bundle)
}

// IAM User tool execution handlers

func (r *ToolRegistry) executeIAMCreateUser(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	req := &IAMCreateUserRequest{
		TenantID:   getString(args, "tenant_id"),
		Email:      getString(args, "email"),
		Name:       getString(args, "name"),
		Roles:      getStringSlice(args, "roles"),
		Groups:     getStringSlice(args, "groups"),
		Attributes: getStringMap(args, "attributes"),
	}

	user, err := r.service.IAMCreateUser(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(user)
}

func (r *ToolRegistry) executeIAMDeleteUser(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")
	userID := getString(args, "user_id")

	if err := r.service.IAMDeleteUser(ctx, tenantID, userID); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeIAMGetUser(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")
	userID := getString(args, "user_id")

	user, err := r.service.IAMGetUser(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	return marshalResult(user)
}

func (r *ToolRegistry) executeIAMListUsers(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")
	limit := getInt(args, "limit")
	offset := getInt(args, "offset")

	if limit == 0 {
		limit = 50
	}

	users, err := r.service.IAMListUsers(ctx, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	return marshalResult(users)
}

// IAM Role tool execution handlers

func (r *ToolRegistry) executeIAMCreateRole(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	req := &IAMCreateRoleRequest{
		TenantID:    getString(args, "tenant_id"),
		ID:          getString(args, "id"),
		Name:        getString(args, "name"),
		Description: getString(args, "description"),
		Permissions: getStringSlice(args, "permissions"),
	}

	role, err := r.service.IAMCreateRole(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(role)
}

func (r *ToolRegistry) executeIAMDeleteRole(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")
	roleID := getString(args, "role_id")

	if err := r.service.IAMDeleteRole(ctx, tenantID, roleID); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeIAMGetRole(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")
	roleID := getString(args, "role_id")

	role, err := r.service.IAMGetRole(ctx, tenantID, roleID)
	if err != nil {
		return nil, err
	}
	return marshalResult(role)
}

func (r *ToolRegistry) executeIAMListRoles(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")
	limit := getInt(args, "limit")
	offset := getInt(args, "offset")

	if limit == 0 {
		limit = 50
	}

	roles, err := r.service.IAMListRoles(ctx, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	return marshalResult(roles)
}

func (r *ToolRegistry) executeIAMAssignRole(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")
	userID := getString(args, "user_id")
	role := getString(args, "role")

	if err := r.service.IAMAssignRole(ctx, tenantID, userID, role); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeIAMRevokeRole(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")
	userID := getString(args, "user_id")
	role := getString(args, "role")

	if err := r.service.IAMRevokeRole(ctx, tenantID, userID, role); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeIAMCheckPermission(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")
	userID := getString(args, "user_id")
	resource := getString(args, "resource")
	action := getString(args, "action")

	allowed, err := r.service.IAMCheckPermission(ctx, tenantID, userID, resource, action)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"allowed":   allowed,
		"tenant_id": tenantID,
		"user_id":   userID,
		"resource":  resource,
		"action":    action,
	}, nil
}

func (r *ToolRegistry) executeIAMAuthenticate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	req := &IAMAuthenticateRequest{
		TenantID:    getString(args, "tenant_id"),
		Email:       getString(args, "email"),
		Password:    getString(args, "password"),
		TOTPCode:    getString(args, "totp_code"),
		Certificate: getString(args, "certificate"),
	}

	result, err := r.service.IAMAuthenticate(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// IAM Group tool execution handlers

func (r *ToolRegistry) executeIAMCreateGroup(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	req := &IAMCreateGroupRequest{
		TenantID:    getString(args, "tenant_id"),
		ID:          getString(args, "id"),
		Name:        getString(args, "name"),
		Description: getString(args, "description"),
	}

	group, err := r.service.IAMCreateGroup(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(group)
}

func (r *ToolRegistry) executeIAMDeleteGroup(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")
	groupID := getString(args, "group_id")

	if err := r.service.IAMDeleteGroup(ctx, tenantID, groupID); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeIAMGetGroup(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")
	groupID := getString(args, "group_id")

	group, err := r.service.IAMGetGroup(ctx, tenantID, groupID)
	if err != nil {
		return nil, err
	}
	return marshalResult(group)
}

func (r *ToolRegistry) executeIAMListGroups(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")
	limit := getInt(args, "limit")
	offset := getInt(args, "offset")

	if limit == 0 {
		limit = 50
	}

	groups, err := r.service.IAMListGroups(ctx, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	return marshalResult(groups)
}

func (r *ToolRegistry) executeIAMAddGroupMember(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")
	groupID := getString(args, "group_id")
	userID := getString(args, "user_id")

	if err := r.service.IAMAddGroupMember(ctx, tenantID, groupID, userID); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeIAMRemoveGroupMember(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")
	groupID := getString(args, "group_id")
	userID := getString(args, "user_id")

	if err := r.service.IAMRemoveGroupMember(ctx, tenantID, groupID, userID); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

// IAM Tenant tool execution handlers

func (r *ToolRegistry) executeIAMCreateTenant(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	req := &IAMCreateTenantRequest{
		ID:   getString(args, "id"),
		Name: getString(args, "name"),
	}

	// Handle settings
	maxUsers := getInt(args, "max_users")
	mfaRequired := getBool(args, "mfa_required")
	if maxUsers > 0 || mfaRequired {
		req.Settings = &IAMTenantSettings{
			MaxUsers:    int32(maxUsers),
			MFARequired: mfaRequired,
		}
	}

	tenant, err := r.service.IAMCreateTenant(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(tenant)
}

func (r *ToolRegistry) executeIAMDeleteTenant(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")

	if err := r.service.IAMDeleteTenant(ctx, tenantID); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeIAMGetTenant(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tenantID := getString(args, "tenant_id")

	tenant, err := r.service.IAMGetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return marshalResult(tenant)
}

func (r *ToolRegistry) executeIAMListTenants(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	limit := getInt(args, "limit")
	offset := getInt(args, "offset")

	if limit == 0 {
		limit = 50
	}

	tenants, err := r.service.IAMListTenants(ctx, limit, offset)
	if err != nil {
		return nil, err
	}
	return marshalResult(tenants)
}

// IAM Token tool execution handlers

func (r *ToolRegistry) executeIAMCreateToken(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	req := &IAMCreateTokenRequest{
		TenantID:    getString(args, "tenant_id"),
		UserID:      getString(args, "user_id"),
		Scopes:      getStringSlice(args, "scopes"),
		ExpiresIn:   getInt64(args, "expires_in"),
		Description: getString(args, "description"),
	}

	// Set default expiration if not provided
	if req.ExpiresIn == 0 {
		req.ExpiresIn = 3600 // 1 hour default
	}

	token, err := r.service.IAMCreateToken(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(token)
}

func (r *ToolRegistry) executeIAMRevokeToken(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	tokenID := getString(args, "token_id")

	if err := r.service.IAMRevokeToken(ctx, tokenID); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeIAMVerifyToken(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	token := getString(args, "token")

	result, err := r.service.IAMVerifyToken(ctx, token)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// =============================================================================
// KMS Tool Execution Functions
// =============================================================================

func (r *ToolRegistry) executeKMSSign(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	messageB64 := getString(args, "message")
	if messageB64 == "" {
		return nil, &mcpwire.MessageError{Msg: "message is required"}
	}
	message, err := base64.StdEncoding.DecodeString(messageB64)
	if err != nil {
		return nil, &mcpwire.WrappedError{Msg: "message must be base64 encoded", Err: err}
	}

	req := &KMSSignRequest{
		KeyID:         getString(args, "key_id"),
		Message:       message,
		HashAlgorithm: signHashAlgorithmName(args),
		PreHashed:     getBool(args, "pre_hashed"),
	}

	if req.KeyID == "" {
		return nil, &mcpwire.MessageError{Msg: "key_id is required"}
	}

	result, err := r.service.KMSSign(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// signHashAlgorithmName normalizes the kms_sign hash_algorithm argument to a
// canonical algorithm name. String values pass through verbatim; numeric
// values use the platform.v1 HashAlgorithm enum numbering, which is what the
// SDK MCP transport adapter emits when it JSON-encodes a proto SignRequest.
func signHashAlgorithmName(args map[string]interface{}) string {
	if s := getString(args, "hash_algorithm"); s != "" {
		return s
	}
	switch getInt(args, "hash_algorithm") {
	case 3:
		return "SHA384"
	case 4:
		return "SHA512"
	default:
		return "SHA256"
	}
}

func (r *ToolRegistry) executeKMSGenerateDataKey(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	req := &KMSGenerateDataKeyRequest{
		KeyID:     getString(args, "key_id"),
		Algorithm: getString(args, "algorithm"),
		Context:   getString(args, "context"),
	}

	if req.KeyID == "" {
		return nil, &mcpwire.MessageError{Msg: "key_id is required"}
	}

	result, err := r.service.KMSGenerateDataKey(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeKMSGenerateWrappedDataKey(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	req := &KMSGenerateWrappedDataKeyRequest{
		KeyID:     getString(args, "key_id"),
		Algorithm: getString(args, "algorithm"),
		Context:   getString(args, "context"),
	}

	if req.KeyID == "" {
		return nil, &mcpwire.MessageError{Msg: "key_id is required"}
	}

	result, err := r.service.KMSGenerateWrappedDataKey(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// =============================================================================
// Container Tool Execution Functions
// =============================================================================

func (r *ToolRegistry) executeContainerCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	if name == "" {
		return nil, ErrContainerNameRequired
	}

	image := getString(args, "image")
	if image == "" {
		return nil, ErrContainerImageRequired
	}

	// Build config map from all optional parameters
	config := make(map[string]interface{})
	if cmd := getStringSlice(args, "command"); len(cmd) > 0 {
		config["command"] = cmd
	}
	if cmdArgs := getStringSlice(args, "args"); len(cmdArgs) > 0 {
		config["args"] = cmdArgs
	}
	if env := getStringMap(args, "env"); len(env) > 0 {
		config["env"] = env
	}
	if labels := getStringMap(args, "labels"); len(labels) > 0 {
		config["labels"] = labels
	}
	if workingDir := getString(args, "working_dir"); workingDir != "" {
		config["working_dir"] = workingDir
	}
	if user := getString(args, "user"); user != "" {
		config["user"] = user
	}
	if _, ok := args["privileged"]; ok {
		config["privileged"] = getBool(args, "privileged")
	}
	if mounts := args["mounts"]; mounts != nil {
		config["mounts"] = mounts
	}
	if ports := args["ports"]; ports != nil {
		config["ports"] = ports
	}
	if resources := args["resources"]; resources != nil {
		config["resources"] = resources
	}

	result, err := r.service.ContainerCreate(ctx, name, image, config)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeContainerStart(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	id := getString(args, "id")
	if id == "" {
		return nil, ErrContainerIDRequired
	}

	if err := r.service.ContainerStart(ctx, id); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeContainerStop(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	id := getString(args, "id")
	if id == "" {
		return nil, ErrContainerIDRequired
	}

	timeout := getInt(args, "timeout")
	if timeout == 0 {
		timeout = 10
	}

	if err := r.service.ContainerStop(ctx, id, timeout); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeContainerRemove(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	id := getString(args, "id")
	if id == "" {
		return nil, ErrContainerIDRequired
	}

	force := getBool(args, "force")

	if err := r.service.ContainerRemove(ctx, id, force); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeContainerGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	id := getString(args, "id")
	if id == "" {
		return nil, ErrContainerIDRequired
	}

	result, err := r.service.ContainerGet(ctx, id)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeContainerList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	all := getBool(args, "all")
	limit := getInt(args, "limit")
	if limit == 0 {
		limit = 50
	}

	// Parse filters from map[string]interface{} to map[string][]string
	filters := make(map[string][]string)
	if filtersArg := getMap(args, "filters"); filtersArg != nil {
		for k, v := range filtersArg {
			switch val := v.(type) {
			case []interface{}:
				strSlice := make([]string, 0, len(val))
				for _, item := range val {
					if s, ok := item.(string); ok {
						strSlice = append(strSlice, s)
					}
				}
				filters[k] = strSlice
			case string:
				filters[k] = []string{val}
			}
		}
	}

	containers, err := r.service.ContainerList(ctx, all, filters, limit)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"containers": containers}, nil
}

func (r *ToolRegistry) executeContainerLogs(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	id := getString(args, "id")
	if id == "" {
		return nil, ErrContainerIDRequired
	}

	// follow is not used for the synchronous API call
	follow := false
	stdout := true
	stderr := true
	tail := "100"
	timestamps := false

	if _, ok := args["stdout"]; ok {
		stdout = getBool(args, "stdout")
	}
	if _, ok := args["stderr"]; ok {
		stderr = getBool(args, "stderr")
	}
	if t := getString(args, "tail"); t != "" {
		tail = t
	}
	if _, ok := args["timestamps"]; ok {
		timestamps = getBool(args, "timestamps")
	}

	logs, err := r.service.ContainerLogs(ctx, id, follow, stdout, stderr, tail, timestamps)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"logs": logs}, nil
}

func (r *ToolRegistry) executeContainerAttest(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	id := getString(args, "id")
	if id == "" {
		return nil, ErrContainerIDRequired
	}

	result, err := r.service.ContainerAttest(ctx, id)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}
