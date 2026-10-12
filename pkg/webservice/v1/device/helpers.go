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

package device

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// decodeJSONBody decodes the JSON request body into the provided value.
func decodeJSONBody(r *http.Request, v interface{}) error {
	decoder := json.NewDecoder(r.Body)
	return decoder.Decode(v)
}

// parsePaginationQuery extracts pagination parameters from the request.
func parsePaginationQuery(r *http.Request) datastore.PageQuery {
	query := datastore.NewPageQuery()

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			query.Page = page
		}
	}

	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if pageSize, err := strconv.Atoi(pageSizeStr); err == nil && pageSize > 0 {
			if pageSize > maxPageSize {
				pageSize = maxPageSize
			}
			query.PageSize = pageSize
		}
	}

	if sortOrder := r.URL.Query().Get("sort_order"); sortOrder != "" {
		if strings.ToLower(sortOrder) == "desc" || strings.ToLower(sortOrder) == "descending" {
			query.SortOrder = datastore.SortDescending
		} else {
			query.SortOrder = datastore.SortAscending
		}
	}

	return query
}

// handleServiceErr maps service-level errors to HTTP status codes.
func handleServiceErr(responseWriter response.HttpWriter, w http.ResponseWriter, r *http.Request, err error) {
	// Typed validation failures from the service layer are client errors.
	var vlans device.ErrProfileVLANsNotDistinct
	if errors.As(err, &vlans) {
		responseWriter.Error400(w, r, err)
		return
	}

	// No profile matches the identity: not found, not a server fault.
	var noMatch device.ErrNoMatchingConfig
	if errors.As(err, &noMatch) {
		responseWriter.Error404(w, r, err)
		return
	}

	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "invalid device ID") ||
		strings.Contains(errStr, "invalid profile ID") ||
		strings.Contains(errStr, "invalid template ID"):
		responseWriter.Error400(w, r, err)
	case strings.Contains(errStr, "not found") ||
		strings.Contains(errStr, "failed to get"):
		responseWriter.Error404(w, r, err)
	default:
		responseWriter.Error500(w, r, err)
	}
}

// matchRulesRequestToEntity converts MatchRulesRequest to ProfileMatchRules entity.
func matchRulesRequestToEntity(req *MatchRulesRequest) *entities.ProfileMatchRules {
	if req == nil {
		return nil
	}
	return &entities.ProfileMatchRules{
		MACPrefix:         req.MACPrefix,
		SerialPrefix:      req.SerialPrefix,
		Model:             req.Model,
		ModelPattern:      req.ModelPattern,
		SerialPattern:     req.SerialPattern,
		ManufacturerMatch: req.ManufacturerMatch,
		TPMVendor:         req.TPMVendor,
		CustomAttributes:  req.CustomAttributes,
	}
}

// matchRulesEntityToResponse converts ProfileMatchRules entity to MatchRulesResponse.
func matchRulesEntityToResponse(rules *entities.ProfileMatchRules) *MatchRulesResponse {
	if rules == nil {
		return nil
	}
	return &MatchRulesResponse{
		MACPrefix:         rules.MACPrefix,
		SerialPrefix:      rules.SerialPrefix,
		Model:             rules.Model,
		ModelPattern:      rules.ModelPattern,
		SerialPattern:     rules.SerialPattern,
		ManufacturerMatch: rules.ManufacturerMatch,
		TPMVendor:         rules.TPMVendor,
		CustomAttributes:  rules.CustomAttributes,
	}
}
