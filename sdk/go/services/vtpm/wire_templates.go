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

// REST wire codec for the template operations.
//
// The template routes under /api/v1/vtpm/templates speak the same domain JSON
// as the bundle routes: create takes {id, description, ek_algorithm,
// secure_boot_enabled} and replies with the bare template, list replies
// {templates}, delete replies {success, message}, and clone takes {hostname,
// labels} with the template id in the path and replies with the new bundle.

import (
	"encoding/json"
	"fmt"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errRequiredWireField is returned when a request lacks a field the route
// requires, so the call is refused before anything is sent.
type errRequiredWireField struct {
	Field string
}

func (e *errRequiredWireField) Error() string {
	return fmt.Sprintf("vtpm: %s is required", e.Field)
}

// EncodeCreateTemplateRequest flattens a CreateTemplateRequest into the body
// POST /api/v1/vtpm/templates takes. An empty id is refused, an unspecified EK
// algorithm is left out so the server applies its default, and an unknown one
// is refused.
func EncodeCreateTemplateRequest(req *platformv1.CreateTemplateRequest) (map[string]interface{}, error) {
	opts := req.GetOptions()
	if opts.GetId() == "" {
		return nil, &errRequiredWireField{Field: "options.id"}
	}
	body := map[string]interface{}{
		"id":                  opts.GetId(),
		"secure_boot_enabled": opts.GetSecureBootEnabled(),
	}
	if description := opts.GetDescription(); description != "" {
		body["description"] = description
	}
	if alg := opts.GetEkAlgorithm(); alg != platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED {
		wire, ok := ekAlgorithmToWire[alg]
		if !ok {
			return nil, &ErrUnknownWireValue{Kind: "EK algorithm", Value: alg.String()}
		}
		body["ek_algorithm"] = wire
	}
	return body, nil
}

// EncodeCloneTemplateRequest builds the {hostname, labels} body POST
// /api/v1/vtpm/templates/{id}/clone takes; the template id travels in the
// path. An empty hostname is refused.
func EncodeCloneTemplateRequest(req *platformv1.CloneTemplateRequest) (map[string]interface{}, error) {
	opts := req.GetOptions()
	if opts.GetHostname() == "" {
		return nil, &errRequiredWireField{Field: "options.hostname"}
	}
	body := map[string]interface{}{"hostname": opts.GetHostname()}
	if labels := opts.GetLabels(); len(labels) > 0 {
		body["labels"] = labels
	}
	return body, nil
}

// DecodeTemplateJSON decodes the template GET /api/v1/vtpm/templates/{id}
// returns.
func DecodeTemplateJSON(data []byte) (*platformv1.GetTemplateResponse, error) {
	var w templateJSON
	if err := decodeJSON(data, "get template", &w); err != nil {
		return nil, err
	}
	tpl, err := w.toProto()
	if err != nil {
		return nil, err
	}
	return &platformv1.GetTemplateResponse{Template: tpl}, nil
}

// DecodeCreateTemplateJSON decodes the bare template POST
// /api/v1/vtpm/templates returns; the status is the one the gRPC service
// reports for the same success.
func DecodeCreateTemplateJSON(data []byte) (*platformv1.CreateTemplateResponse, error) {
	var w templateJSON
	if err := decodeJSON(data, "create template", &w); err != nil {
		return nil, err
	}
	tpl, err := w.toProto()
	if err != nil {
		return nil, err
	}
	return &platformv1.CreateTemplateResponse{
		Status:   &platformv1.Status{Success: true, Message: "template created successfully"},
		Template: tpl,
	}, nil
}

// DecodeListTemplatesJSON decodes the {templates} GET /api/v1/vtpm/templates
// returns.
func DecodeListTemplatesJSON(data []byte) (*platformv1.ListTemplatesResponse, error) {
	var w struct {
		Templates []templateJSON `json:"templates"`
	}
	if err := decodeJSON(data, "list templates", &w); err != nil {
		return nil, err
	}
	templates := make([]*platformv1.Template, 0, len(w.Templates))
	for i := range w.Templates {
		tpl, err := w.Templates[i].toProto()
		if err != nil {
			return nil, err
		}
		templates = append(templates, tpl)
	}
	return &platformv1.ListTemplatesResponse{Templates: templates}, nil
}

// DecodeDeleteTemplateJSON decodes the {success, message} DELETE
// /api/v1/vtpm/templates/{id} returns.
func DecodeDeleteTemplateJSON(data []byte) (*platformv1.DeleteTemplateResponse, error) {
	var w struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := decodeJSON(data, "delete template", &w); err != nil {
		return nil, err
	}
	return &platformv1.DeleteTemplateResponse{
		Status: &platformv1.Status{Success: w.Success, Message: w.Message},
	}, nil
}

// DecodeCloneTemplateJSON decodes the bundle POST
// /api/v1/vtpm/templates/{id}/clone returns.
func DecodeCloneTemplateJSON(data []byte) (*platformv1.CloneTemplateResponse, error) {
	var probe struct {
		Manifest json.RawMessage `json:"manifest"`
	}
	if err := decodeJSON(data, "clone template", &probe); err != nil {
		return nil, err
	}
	var w bundleJSON
	if len(probe.Manifest) == 0 || string(probe.Manifest) == "null" {
		// The daemon (pkg/api/rest) replies with a flat bundle: the manifest
		// fields sit at the top level.
		var flat flatCloneJSON
		if err := decodeJSON(data, "clone template", &flat); err != nil {
			return nil, err
		}
		w = flat.toBundleJSON()
	} else if err := decodeJSON(data, "clone template", &w); err != nil {
		return nil, err
	}
	bundle, err := w.toProto()
	if err != nil {
		return nil, err
	}
	return &platformv1.CloneTemplateResponse{
		Status: &platformv1.Status{Success: true, Message: "template cloned successfully"},
		Bundle: bundle,
	}, nil
}

// flatCloneJSON is the daemon's clone reply: a bundle whose manifest fields
// are flattened to the top level, with Secure Boot key fingerprints (not key
// paths) under secure_boot_keys.
type flatCloneJSON struct {
	ID                string                 `json:"id"`
	Mode              string                 `json:"mode"`
	Hostname          string                 `json:"hostname"`
	EKAlgorithm       string                 `json:"ek_algorithm"`
	SecureBootEnabled bool                   `json:"secure_boot_enabled"`
	CreatedAt         *time.Time             `json:"created_at"`
	ClonedFrom        string                 `json:"cloned_from"`
	Labels            map[string]string      `json:"labels"`
	EKCertificate     *ekCertJSON            `json:"ek_certificate"`
	SecureBootKeys    *secureBootKeyInfoJSON `json:"secure_boot_keys"`
}

func (f *flatCloneJSON) toBundleJSON() bundleJSON {
	return bundleJSON{
		ID:         f.ID,
		Mode:       f.Mode,
		CreatedAt:  f.CreatedAt,
		ClonedFrom: f.ClonedFrom,
		Manifest: &manifestJSON{
			ID:                f.ID,
			Mode:              f.Mode,
			Hostname:          f.Hostname,
			CreatedAt:         f.CreatedAt,
			EKCertificate:     f.EKCertificate,
			EKAlgorithm:       f.EKAlgorithm,
			SecureBootEnabled: f.SecureBootEnabled,
			SecureBootKeys:    f.SecureBootKeys,
			Labels:            f.Labels,
			ClonedFrom:        f.ClonedFrom,
		},
	}
}

type templateJSON struct {
	ID                string     `json:"id"`
	Description       string     `json:"description"`
	TPMStateDir       string     `json:"tpm_state_dir"`
	NVRAMPath         string     `json:"nvram_path"`
	SecureBootKeysDir string     `json:"secure_boot_keys_dir"`
	EKAlgorithm       string     `json:"ek_algorithm"`
	SecureBootEnabled bool       `json:"secure_boot_enabled"`
	CreatedAt         *time.Time `json:"created_at"`
}

func (w *templateJSON) toProto() (*platformv1.Template, error) {
	alg, err := ekAlgorithmFromWire(w.EKAlgorithm)
	if err != nil {
		return nil, err
	}
	return &platformv1.Template{
		Id:                w.ID,
		Description:       w.Description,
		TpmStateDir:       w.TPMStateDir,
		NvramPath:         w.NVRAMPath,
		SecureBootKeysDir: w.SecureBootKeysDir,
		EkAlgorithm:       alg,
		SecureBootEnabled: w.SecureBootEnabled,
		CreatedAt:         timestampFromWire(w.CreatedAt),
	}, nil
}
