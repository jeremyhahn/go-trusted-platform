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

package vtpm

// REST wire codec for the bundle operations.
//
// The daemon's bundle routes (pkg/webservice/v1/rest/vtpm) speak the domain's
// own JSON: a bundle mode is "template" or "pre-assigned", an EK algorithm is
// "RSA" or "ECC", CreateBundle takes flat options and replies with the bare
// bundle, and DeleteBundle replies {success, message}. These helpers translate
// between that JSON and the platformv1 messages. The runtime replies (start,
// quote, seal, ...) already carry the pb field names and need no codec.

import (
	"encoding/json"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// bundleModeToWire is the daemon's spelling of each settable bundle mode.
var bundleModeToWire = map[platformv1.BundleMode]string{
	platformv1.BundleMode_BUNDLE_MODE_TEMPLATE:     "template",
	platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED: "pre-assigned",
}

// ekAlgorithmToWire is the daemon's spelling of each settable EK algorithm.
var ekAlgorithmToWire = map[platformv1.EKAlgorithm]string{
	platformv1.EKAlgorithm_EK_ALGORITHM_RSA: "RSA",
	platformv1.EKAlgorithm_EK_ALGORITHM_ECC: "ECC",
}

// EncodeCreateBundleRequest flattens a CreateBundleRequest into the JSON body
// POST /api/v1/vtpm/bundles takes. An unspecified mode or EK algorithm is left
// out so the daemon applies its default; an unknown one is refused.
func EncodeCreateBundleRequest(req *platformv1.CreateBundleRequest) (map[string]interface{}, error) {
	opts := req.GetOptions()
	body := map[string]interface{}{
		"secure_boot_enabled": opts.GetSecureBootEnabled(),
	}

	if mode := opts.GetMode(); mode != platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED {
		wire, ok := bundleModeToWire[mode]
		if !ok {
			return nil, &ErrUnknownWireValue{Kind: "bundle mode", Value: mode.String()}
		}
		body["mode"] = wire
	}
	if alg := opts.GetEkAlgorithm(); alg != platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED {
		wire, ok := ekAlgorithmToWire[alg]
		if !ok {
			return nil, &ErrUnknownWireValue{Kind: "EK algorithm", Value: alg.String()}
		}
		body["ek_algorithm"] = wire
	}
	if hostname := opts.GetHostname(); hostname != "" {
		body["hostname"] = hostname
	}
	if labels := opts.GetLabels(); len(labels) > 0 {
		body["labels"] = labels
	}
	if templateID := opts.GetTemplateId(); templateID != "" {
		body["template_id"] = templateID
	}
	if profileID := opts.GetDeviceProfileId(); profileID != 0 {
		body["device_profile_id"] = profileID
	}
	return body, nil
}

// DecodeCreateBundleJSON decodes the bundle POST /api/v1/vtpm/bundles returns.
// The route replies with the bare bundle; the status is the one the gRPC
// service reports for the same success.
func DecodeCreateBundleJSON(data []byte) (*platformv1.CreateBundleResponse, error) {
	var w bundleJSON
	if err := decodeJSON(data, "create bundle", &w); err != nil {
		return nil, err
	}
	bundle, err := w.toProto()
	if err != nil {
		return nil, err
	}
	return &platformv1.CreateBundleResponse{
		Status: &platformv1.Status{Success: true, Message: "bundle created successfully"},
		Bundle: bundle,
	}, nil
}

// DecodeListBundlesJSON decodes the {bundles, total} GET /api/v1/vtpm/bundles
// returns.
func DecodeListBundlesJSON(data []byte) (*platformv1.ListBundlesResponse, error) {
	var w struct {
		Bundles []bundleJSON `json:"bundles"`
		Total   int32        `json:"total"`
	}
	if err := decodeJSON(data, "list bundles", &w); err != nil {
		return nil, err
	}
	bundles := make([]*platformv1.Bundle, 0, len(w.Bundles))
	for i := range w.Bundles {
		bundle, err := w.Bundles[i].toProto()
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}
	return &platformv1.ListBundlesResponse{Bundles: bundles, Total: w.Total}, nil
}

// DecodeDeleteBundleJSON decodes the {success, message} DELETE
// /api/v1/vtpm/bundles/{id} returns.
func DecodeDeleteBundleJSON(data []byte) (*platformv1.DeleteBundleResponse, error) {
	var w struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := decodeJSON(data, "delete bundle", &w); err != nil {
		return nil, err
	}
	return &platformv1.DeleteBundleResponse{
		Status: &platformv1.Status{Success: w.Success, Message: w.Message},
	}, nil
}

func decodeJSON(data []byte, message string, v interface{}) error {
	if err := json.Unmarshal(data, v); err != nil {
		return &ErrWireDecode{Message: message, Err: err}
	}
	return nil
}

// bundleModeFromWire maps the daemon's mode string to the proto enum; an
// empty string is UNSPECIFIED and anything unrecognised is refused.
func bundleModeFromWire(s string) (platformv1.BundleMode, error) {
	if s == "" {
		return platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED, nil
	}
	mode, ok := ParseBundleMode(s)
	if !ok {
		return platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED, &ErrUnknownWireValue{Kind: "bundle mode", Value: s}
	}
	return BundleModeToProto(mode), nil
}

// ekAlgorithmFromWire maps the daemon's EK algorithm string to the proto
// enum; an empty string is UNSPECIFIED and anything unrecognised is refused.
func ekAlgorithmFromWire(s string) (platformv1.EKAlgorithm, error) {
	if s == "" {
		return platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED, nil
	}
	alg, ok := ParseEKAlgorithm(s)
	if !ok {
		return platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED, &ErrUnknownWireValue{Kind: "EK algorithm", Value: s}
	}
	return EKAlgorithmToProto(alg), nil
}

func timestampFromWire(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

type bundleJSON struct {
	ID             string              `json:"id"`
	Mode           string              `json:"mode"`
	Manifest       *manifestJSON       `json:"manifest"`
	TPMState       *tpmStateJSON       `json:"tpm_state"`
	OVMFState      *ovmfStateJSON      `json:"ovmf_state"`
	SecureBootKeys *secureBootKeysJSON `json:"secure_boot_keys"`
	CreatedAt      *time.Time          `json:"created_at"`
	ClonedFrom     string              `json:"cloned_from"`
}

func (w *bundleJSON) toProto() (*platformv1.Bundle, error) {
	mode, err := bundleModeFromWire(w.Mode)
	if err != nil {
		return nil, err
	}
	manifest, err := w.Manifest.toProto()
	if err != nil {
		return nil, err
	}
	return &platformv1.Bundle{
		Id:             w.ID,
		Mode:           mode,
		Manifest:       manifest,
		TpmState:       w.TPMState.toProto(),
		OvmfState:      w.OVMFState.toProto(),
		SecureBootKeys: w.SecureBootKeys.toProto(),
		CreatedAt:      timestampFromWire(w.CreatedAt),
		ClonedFrom:     w.ClonedFrom,
	}, nil
}

type manifestJSON struct {
	Version           string                 `json:"version"`
	ID                string                 `json:"id"`
	Mode              string                 `json:"mode"`
	Hostname          string                 `json:"hostname"`
	CreatedAt         *time.Time             `json:"created_at"`
	EKCertificate     *ekCertJSON            `json:"ek_certificate"`
	EKAlgorithm       string                 `json:"ek_algorithm"`
	EKHandle          uint32                 `json:"ek_handle"`
	SecureBootEnabled bool                   `json:"secure_boot_enabled"`
	SecureBootKeys    *secureBootKeyInfoJSON `json:"secure_boot_keys"`
	Checksums         map[string]string      `json:"checksums"`
	Labels            map[string]string      `json:"labels"`
	ClonedFrom        string                 `json:"cloned_from"`
	DeviceProfileID   uint64                 `json:"device_profile_id"`
}

func (w *manifestJSON) toProto() (*platformv1.Manifest, error) {
	if w == nil {
		return nil, nil
	}
	mode, err := bundleModeFromWire(w.Mode)
	if err != nil {
		return nil, err
	}
	alg, err := ekAlgorithmFromWire(w.EKAlgorithm)
	if err != nil {
		return nil, err
	}
	return &platformv1.Manifest{
		Version:           w.Version,
		Id:                w.ID,
		Mode:              mode,
		Hostname:          w.Hostname,
		CreatedAt:         timestampFromWire(w.CreatedAt),
		EkCertificate:     w.EKCertificate.toProto(),
		EkAlgorithm:       alg,
		EkHandle:          w.EKHandle,
		SecureBootEnabled: w.SecureBootEnabled,
		SecureBootKeys:    w.SecureBootKeys.toProto(),
		Checksums:         w.Checksums,
		Labels:            w.Labels,
		ClonedFrom:        w.ClonedFrom,
		DeviceProfileId:   w.DeviceProfileID,
	}, nil
}

type ekCertJSON struct {
	Subject      string     `json:"subject"`
	Issuer       string     `json:"issuer"`
	SerialNumber string     `json:"serial_number"`
	NotBefore    *time.Time `json:"not_before"`
	NotAfter     *time.Time `json:"not_after"`
	Fingerprint  string     `json:"fingerprint"`
}

func (w *ekCertJSON) toProto() *platformv1.EKCertInfo {
	if w == nil {
		return nil
	}
	return &platformv1.EKCertInfo{
		Subject:      w.Subject,
		Issuer:       w.Issuer,
		SerialNumber: w.SerialNumber,
		NotBefore:    timestampFromWire(w.NotBefore),
		NotAfter:     timestampFromWire(w.NotAfter),
		Fingerprint:  w.Fingerprint,
	}
}

type secureBootKeyInfoJSON struct {
	PKFingerprint  string `json:"pk_fingerprint"`
	KEKFingerprint string `json:"kek_fingerprint"`
	DBFingerprint  string `json:"db_fingerprint"`
	OwnerGUID      string `json:"owner_guid"`
}

func (w *secureBootKeyInfoJSON) toProto() *platformv1.SecureBootKeyInfo {
	if w == nil {
		return nil
	}
	return &platformv1.SecureBootKeyInfo{
		PkFingerprint:  w.PKFingerprint,
		KekFingerprint: w.KEKFingerprint,
		DbFingerprint:  w.DBFingerprint,
		OwnerGuid:      w.OwnerGUID,
	}
}

type secureBootKeysJSON struct {
	Dir     string `json:"dir"`
	PKKey   string `json:"pk_key"`
	PKCert  string `json:"pk_crt"`
	KEKKey  string `json:"kek_key"`
	KEKCert string `json:"kek_crt"`
	DBKey   string `json:"db_key"`
	DBCert  string `json:"db_crt"`
}

func (w *secureBootKeysJSON) toProto() *platformv1.SecureBootKeyPaths {
	if w == nil {
		return nil
	}
	return &platformv1.SecureBootKeyPaths{
		Dir:    w.Dir,
		PkKey:  w.PKKey,
		PkCrt:  w.PKCert,
		KekKey: w.KEKKey,
		KekCrt: w.KEKCert,
		DbKey:  w.DBKey,
		DbCrt:  w.DBCert,
	}
}

type tpmStateJSON struct {
	StateDir     string `json:"state_dir"`
	PermallFile  string `json:"permall_file"`
	VolatileFile string `json:"volatile_file"`
}

func (w *tpmStateJSON) toProto() *platformv1.TPMState {
	if w == nil {
		return nil
	}
	return &platformv1.TPMState{
		StateDir:     w.StateDir,
		PermallFile:  w.PermallFile,
		VolatileFile: w.VolatileFile,
	}
}

type ovmfStateJSON struct {
	NVRAMFile string `json:"nvram_file"`
}

func (w *ovmfStateJSON) toProto() *platformv1.OVMFState {
	if w == nil {
		return nil
	}
	return &platformv1.OVMFState{NvramFile: w.NVRAMFile}
}
