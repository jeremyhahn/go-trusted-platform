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

package platform

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// maxConfigUpdateBody caps the PUT /config/sections/{section} body.
const maxConfigUpdateBody = 1 << 20

// ConfigUpdater narrows the surface UpdateConfigSection needs from the
// daemon.Service: PlatformDaemon.UpdateConfig, which applies one config
// section (taking a pre-update snapshot when a store is wired) and
// optionally persists it to the config file. Defined as an interface so
// tests can stand in a fake.
type ConfigUpdater interface {
	UpdateConfig(ctx context.Context, req *platformv1.UpdateConfigRequest) (*platformv1.UpdateConfigResponse, error)
}

// SetConfigUpdater hooks up the daemon.Service (or a fake) used by the
// PUT /platform/config/sections/{section} handler. When unset, the
// handler returns 503.
func (h *PlatformHandlers) SetConfigUpdater(u ConfigUpdater) {
	h.configUpdater = u
}

// ConfigSectionUpdateRequest is the PUT /config/sections/{section} body.
type ConfigSectionUpdateRequest struct {
	Values  map[string]string `json:"values"`
	Persist bool              `json:"persist"`
}

// ConfigSectionUpdateResponse is the PUT /config/sections/{section}
// reply. It never echoes the applied values, which can be secrets.
type ConfigSectionUpdateResponse struct {
	Section   string `json:"section"`
	Persisted bool   `json:"persisted"`
	Message   string `json:"message"`
}

// UpdateConfigSection handles PUT /api/v1/platform/config/sections/{section}.
// It applies the body's values to one config section through
// PlatformDaemon.UpdateConfig and, when persist is true, writes the
// section to the config file. The service takes a pre-update snapshot
// when a store is wired, so the change can be rolled back through
// POST /config/snapshots/{id}/rollback. The values are never logged or
// echoed in the reply.
func (h *PlatformHandlers) UpdateConfigSection(w http.ResponseWriter, r *http.Request) {
	if h.configUpdater == nil {
		h.respWriter.Error503(w, r, ErrConfigUpdaterUnavailable{})
		return
	}
	section := mux.Vars(r)["section"]

	var req ConfigSectionUpdateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxConfigUpdateBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		h.respWriter.Error400(w, r, ErrConfigUpdateBody{Cause: err})
		return
	}
	if len(req.Values) == 0 {
		h.respWriter.Error400(w, r, ErrConfigValuesRequired{})
		return
	}
	for k := range req.Values {
		if k == "" {
			h.respWriter.Error400(w, r, ErrConfigKeyRequired{})
			return
		}
	}

	resp, err := h.configUpdater.UpdateConfig(r.Context(), &platformv1.UpdateConfigRequest{
		Section: &platformv1.ConfigSection{Section: section, Values: req.Values},
		Persist: req.Persist,
	})
	if err != nil {
		if status.Code(err) == codes.InvalidArgument {
			h.respWriter.Error400(w, r, err)
			return
		}
		h.respWriter.Error500(w, r, err)
		return
	}
	h.respWriter.Success200(w, r, ConfigSectionUpdateResponse{
		Section:   section,
		Persisted: req.Persist,
		Message:   resp.GetStatus().GetMessage(),
	})
}

// ErrConfigUpdaterUnavailable is returned when the section update
// handler is invoked before SetConfigUpdater has been wired.
type ErrConfigUpdaterUnavailable struct{}

func (ErrConfigUpdaterUnavailable) Error() string {
	return "platform: config updater is not configured on this daemon"
}

// ErrConfigValuesRequired is returned when a section update carries no
// values.
type ErrConfigValuesRequired struct{}

func (ErrConfigValuesRequired) Error() string {
	return "platform: values is required"
}

// ErrConfigKeyRequired is returned when a section update carries an
// empty key.
type ErrConfigKeyRequired struct{}

func (ErrConfigKeyRequired) Error() string {
	return "platform: config key is required"
}

// ErrConfigUpdateBody is returned when the section update body does not
// decode.
type ErrConfigUpdateBody struct {
	Cause error
}

func (e ErrConfigUpdateBody) Error() string {
	return "platform: malformed config update body: " + e.Cause.Error()
}
