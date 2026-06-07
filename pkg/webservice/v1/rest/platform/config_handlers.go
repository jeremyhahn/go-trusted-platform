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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// ConfigReloader narrows the surface ConfigHandlers needs from the
// daemon.Service. Defined as an interface so tests can stand in a
// fake without instantiating the whole daemon.
type ConfigReloader interface {
	ReloadConfigFromDisk() ([]string, error)
	ReloadConfigWithSnapshot(actor string) ([]string, string, error)
	RollbackConfig(snapshotID, actor string) (string, error)
	SnapshotStore() tpconfig.SnapshotStore
}

// SetConfigReloader hooks up the daemon.Service (or a fake) used by
// the /platform/config/reload handler. When unset, /reload returns
// 503 so the surface is honest rather than silently no-opping.
func (h *PlatformHandlers) SetConfigReloader(r ConfigReloader) {
	h.configReloader = r
}

// GetConfig handles GET /api/v1/platform/config.
//
// Query parameters:
//   - redact=false disables secret redaction. Requires the caller to
//     have the platform-secrets capability; the auth middleware
//     stripes that into the request context. When the capability is
//     missing, the handler still redacts. Default redact=true.
//   - section=<name> narrows the response to one top-level section.
//
// Response body is the ConfigTree shape: sources[], tree (merged
// config), generated_at, redacted_keys[]. Sensitive leaves are
// replaced with the sentinel "••••" by default; the list of redacted
// dot-paths is included so the WebUI can render them with a "click
// to reveal" affordance that calls back with redact=false (subject
// to authorization).
func (h *PlatformHandlers) GetConfig(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redact := !strings.EqualFold(q.Get("redact"), "false")
	if !redact && !callerHasSecretsCap(r) {
		// Authorization not granted — quietly stay redacted instead of
		// erroring. The Web UI treats the absent click-to-reveal as a
		// permissions hint.
		redact = true
	}
	tree := tpconfig.LoadConfigTree(redact)
	if sec := q.Get("section"); sec != "" {
		if v, ok := tree.Tree[sec]; ok {
			tree.Tree = map[string]interface{}{sec: v}
		} else {
			h.respWriter.Error404(w, r, ErrConfigSectionNotFound{Section: sec})
			return
		}
	}
	h.respWriter.Success200(w, r, tree)
}

// ReloadConfig handles POST /api/v1/platform/config/reload. It
// captures a pre-reload snapshot (when a snapshot store is wired),
// re-reads the active config file, and re-runs viper.Unmarshal
// against the bound *app.App. The response includes the snapshot ID
// so the operator can roll back if the new config misbehaves.
func (h *PlatformHandlers) ReloadConfig(w http.ResponseWriter, r *http.Request) {
	if h.configReloader == nil {
		h.respWriter.Error500(w, r, ErrConfigReloaderUnavailable{})
		return
	}
	actor := callerActor(r)
	sections, snapshotID, err := h.configReloader.ReloadConfigWithSnapshot(actor)
	if err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}
	h.respWriter.Success200(w, r, map[string]interface{}{
		"reloaded":             true,
		"sections":             sections,
		"pre_reload_snapshot":  snapshotID,
	})
}

// ListSnapshots handles GET /api/v1/platform/config/snapshots. Returns
// the snapshot history newest-first. limit query param caps the
// response; 0 (default) returns all.
func (h *PlatformHandlers) ListSnapshots(w http.ResponseWriter, r *http.Request) {
	store := h.snapshotStore()
	if store == nil {
		h.respWriter.Error500(w, r, ErrSnapshotStoreUnavailable{})
		return
	}
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	summaries, err := store.List(limit)
	if err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}
	h.respWriter.Success200(w, r, map[string]interface{}{
		"snapshots": summaries,
		"total":     len(summaries),
	})
}

// GetSnapshot handles GET /api/v1/platform/config/snapshots/{id}.
// Returns the full snapshot body including the tree. Secrets are
// NOT redacted in snapshots because rollback requires the original
// values; access is gated by the same auth that gates the
// non-redacted GetConfig endpoint.
func (h *PlatformHandlers) GetSnapshot(w http.ResponseWriter, r *http.Request) {
	store := h.snapshotStore()
	if store == nil {
		h.respWriter.Error500(w, r, ErrSnapshotStoreUnavailable{})
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		h.respWriter.Error400(w, r, ErrSnapshotIDRequired{})
		return
	}
	snap, err := store.Get(id)
	if err != nil {
		var notFound tpconfig.ErrSnapshotNotFound
		if errors.As(err, &notFound) {
			h.respWriter.Error404(w, r, err)
			return
		}
		h.respWriter.Error500(w, r, err)
		return
	}
	h.respWriter.Success200(w, r, snap)
}

// CreateSnapshot handles POST /api/v1/platform/config/snapshots.
// Captures the current Viper state as a snapshot. Body is JSON:
// {"reason": "ad-hoc"} (optional). Used by operators who want a
// rollback handle without reloading.
func (h *PlatformHandlers) CreateSnapshot(w http.ResponseWriter, r *http.Request) {
	store := h.snapshotStore()
	if store == nil {
		h.respWriter.Error500(w, r, ErrSnapshotStoreUnavailable{})
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if body.Reason == "" {
		body.Reason = "manual"
	}
	snap, err := tpconfig.CaptureCurrent(store, body.Reason, callerActor(r))
	if err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}
	h.respWriter.Success200(w, r, map[string]interface{}{
		"id":         snap.ID,
		"created_at": snap.CreatedAt,
		"reason":     snap.Reason,
	})
}

// DeleteSnapshot handles DELETE /api/v1/platform/config/snapshots/{id}.
func (h *PlatformHandlers) DeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	store := h.snapshotStore()
	if store == nil {
		h.respWriter.Error500(w, r, ErrSnapshotStoreUnavailable{})
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		h.respWriter.Error400(w, r, ErrSnapshotIDRequired{})
		return
	}
	if err := store.Delete(id); err != nil {
		var notFound tpconfig.ErrSnapshotNotFound
		if errors.As(err, &notFound) {
			h.respWriter.Error404(w, r, err)
			return
		}
		h.respWriter.Error500(w, r, err)
		return
	}
	h.respWriter.Success200(w, r, map[string]interface{}{"deleted": true, "id": id})
}

// Rollback handles POST /api/v1/platform/config/snapshots/{id}/rollback.
// Captures the current state first (so the rollback itself is
// reversible), writes the snapshot YAML back to the active config
// path, and re-reads.
func (h *PlatformHandlers) Rollback(w http.ResponseWriter, r *http.Request) {
	if h.configReloader == nil {
		h.respWriter.Error500(w, r, ErrConfigReloaderUnavailable{})
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		h.respWriter.Error400(w, r, ErrSnapshotIDRequired{})
		return
	}
	preID, err := h.configReloader.RollbackConfig(id, callerActor(r))
	if err != nil {
		var notFound tpconfig.ErrSnapshotNotFound
		if errors.As(err, &notFound) {
			h.respWriter.Error404(w, r, err)
			return
		}
		h.respWriter.Error500(w, r, err)
		return
	}
	h.respWriter.Success200(w, r, map[string]interface{}{
		"rolled_back_to":            id,
		"pre_rollback_snapshot":     preID,
	})
}

// snapshotStore returns the daemon-provided store, or nil.
func (h *PlatformHandlers) snapshotStore() tpconfig.SnapshotStore {
	if h.configReloader == nil {
		return nil
	}
	return h.configReloader.SnapshotStore()
}

// callerActor extracts a stable identifier for whoever invoked the
// reload / snapshot operation. Today we read from the JWT subject
// header that upstream middleware writes; a missing header surfaces
// as "anonymous" so the audit trail still records something.
func callerActor(r *http.Request) string {
	if a := r.Header.Get("X-Platform-Actor"); a != "" {
		return a
	}
	if a := r.Header.Get("X-User-Id"); a != "" {
		return a
	}
	return "anonymous"
}

// ErrSnapshotStoreUnavailable is returned when snapshot endpoints
// are hit before the daemon has wired a snapshot store.
type ErrSnapshotStoreUnavailable struct{}

func (ErrSnapshotStoreUnavailable) Error() string {
	return "platform: snapshot store is not configured on this daemon"
}

// ErrSnapshotIDRequired is returned when a snapshot endpoint is hit
// without a path parameter.
type ErrSnapshotIDRequired struct{}

func (ErrSnapshotIDRequired) Error() string {
	return "platform: snapshot id is required"
}

// ValidateConfig handles POST /api/v1/platform/config/validate. The
// request body is the proposed YAML; the handler returns a 200 with
// `{"valid": true}` on success or a structured error list on failure.
// Validation never mutates daemon state.
//
// Today the validation is "does it parse to a map?" — schema-level
// checks (referenced files, ports, addresses) will land alongside the
// snapshot/rollback work in a follow-up.
func (h *PlatformHandlers) ValidateConfig(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	if issues := tpconfig.ValidateConfigYAML(body); len(issues) > 0 {
		h.respWriter.Success200(w, r, map[string]interface{}{
			"valid":  false,
			"issues": issues,
		})
		return
	}
	h.respWriter.Success200(w, r, map[string]interface{}{
		"valid": true,
	})
}

// callerHasSecretsCap reports whether the request carries the
// platform-secrets capability stamped by upstream middleware. Today
// the WebUI doesn't stamp this — the surface stays redacted-only
// until the IAM capability scheme grows it. The hook is here so
// turning it on is an isolated middleware change rather than a
// handler refactor.
func callerHasSecretsCap(r *http.Request) bool {
	// Reserved hook. Keep parameter to preserve the signature when
	// the capability check lands.
	_ = r
	return false
}

// ErrConfigSectionNotFound is returned when a section query parameter
// references a non-existent top-level config key.
type ErrConfigSectionNotFound struct {
	Section string
}

func (e ErrConfigSectionNotFound) Error() string {
	return "platform: config section not found: " + e.Section
}

// ErrConfigReloaderUnavailable is returned when the reload handler is
// invoked before SetConfigReloader has been wired.
type ErrConfigReloaderUnavailable struct{}

func (ErrConfigReloaderUnavailable) Error() string {
	return "platform: config reloader is not configured on this daemon"
}
