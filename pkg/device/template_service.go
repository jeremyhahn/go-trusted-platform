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
	"context"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// Compile-time interface check.
var _ DeviceTemplateService = (*TemplateService)(nil)

// TemplateService provides business logic for device templates.
type TemplateService struct {
	templateDAO dao.DeviceTemplateDAO
	profileDAO  dao.DeviceProfileDAO
}

// NewTemplateService creates a new template service using the provided Datastore.
func NewTemplateService(ds *Datastore) (*TemplateService, error) {
	templateDAO, err := ds.TemplateDAO()
	if err != nil {
		return nil, fmt.Errorf("failed to get template DAO: %w", err)
	}

	profileDAO, err := ds.ProfileDAO()
	if err != nil {
		return nil, fmt.Errorf("failed to get profile DAO: %w", err)
	}

	return &TemplateService{
		templateDAO: templateDAO,
		profileDAO:  profileDAO,
	}, nil
}

// Save persists a device template. The template must have a non-zero ID.
func (s *TemplateService) Save(ctx context.Context, template *entities.DeviceTemplate) error {
	if template == nil {
		return ErrNilTemplate{}
	}

	if template.ID == 0 {
		return ErrInvalidTemplateID{}
	}

	if template.CreatedAt.IsZero() {
		template.CreatedAt = time.Now()
	}
	template.UpdatedAt = time.Now()

	if err := s.templateDAO.Save(ctx, template); err != nil {
		return fmt.Errorf("failed to save template: %w", err)
	}

	return nil
}

// Get retrieves a device template by its ID.
func (s *TemplateService) Get(ctx context.Context, id uint64) (*entities.DeviceTemplate, error) {
	if id == 0 {
		return nil, ErrInvalidTemplateID{}
	}

	template, err := s.templateDAO.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	return template, nil
}

// Delete removes a device template from storage.
func (s *TemplateService) Delete(ctx context.Context, template *entities.DeviceTemplate) error {
	if template == nil {
		return ErrNilTemplate{}
	}

	if template.ID == 0 {
		return ErrInvalidTemplateID{}
	}

	if err := s.templateDAO.Delete(ctx, template); err != nil {
		return fmt.Errorf("failed to delete template: %w", err)
	}

	return nil
}

// Update modifies an existing device template. The template must exist.
func (s *TemplateService) Update(ctx context.Context, template *entities.DeviceTemplate) error {
	if template == nil {
		return ErrNilTemplate{}
	}

	if template.ID == 0 {
		return ErrInvalidTemplateID{}
	}

	// Verify template exists before updating
	_, err := s.templateDAO.Get(ctx, template.ID)
	if err != nil {
		return fmt.Errorf("failed to get template for update: %w", err)
	}

	template.UpdatedAt = time.Now()

	if err := s.templateDAO.Save(ctx, template); err != nil {
		return fmt.Errorf("failed to update template: %w", err)
	}

	return nil
}

// Count returns the total number of device templates.
func (s *TemplateService) Count(ctx context.Context) (int, error) {
	count, err := s.templateDAO.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count templates: %w", err)
	}
	return count, nil
}

// Page retrieves a paginated list of device templates.
func (s *TemplateService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceTemplate], error) {
	result, err := s.templateDAO.Page(ctx, query)
	if err != nil {
		return datastore.PageResult[*entities.DeviceTemplate]{}, fmt.Errorf("failed to page templates: %w", err)
	}
	return result, nil
}

// FindByName finds a template by its name within a tenant.
func (s *TemplateService) FindByName(ctx context.Context, tenantID, name string) (*entities.DeviceTemplate, error) {
	if name == "" {
		return nil, ErrTemplateNameRequired{}
	}

	template, err := s.templateDAO.FindByName(ctx, tenantID, name)
	if err != nil {
		return nil, fmt.Errorf("failed to find template by name: %w", err)
	}

	return template, nil
}

// ToProfile deep-copies the template config into a new DeviceProfile with optional overrides.
// It does NOT save the profile -- the caller is responsible for saving.
//
// The template's Config (raw YAML bytes) is stored in the profile's PlatformdConfig
// as an inline configuration. The raw bytes are unmarshaled into a generic map
// to produce a clean deep copy without importing the app package.
func (s *TemplateService) ToProfile(ctx context.Context, templateID uint64, overrides *entities.DeviceProfile) (*entities.DeviceProfile, error) {
	if templateID == 0 {
		return nil, ErrInvalidTemplateID{}
	}

	template, err := s.templateDAO.Get(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get template for profile conversion: %w", err)
	}

	profile := &entities.DeviceProfile{
		TenantID: template.TenantID,
		Role:     template.Role,
	}

	// Deep-copy the template config into a PlatformdConfigRef.
	// The template stores raw YAML bytes; unmarshal into a generic map
	// for the inline config to avoid import cycles with the app package.
	if len(template.Config) > 0 {
		var configMap map[string]interface{}
		if err := yaml.Unmarshal(template.Config, &configMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal template config: %w", err)
		}
		profile.PlatformdConfig = &entities.PlatformdConfigRef{
			ConfigType: "inline",
			Inline:     configMap,
		}
	}

	// Deep-copy match rules via YAML round-trip
	if template.MatchRules != nil {
		rulesCopy, err := deepCopyMatchRules(template.MatchRules)
		if err != nil {
			return nil, fmt.Errorf("failed to deep copy match rules: %w", err)
		}
		profile.MatchRules = rulesCopy
	}

	// Apply overrides from the caller
	if overrides != nil {
		if overrides.ID != 0 {
			profile.ID = overrides.ID
		}
		if overrides.TenantID != "" {
			profile.TenantID = overrides.TenantID
		}
		if overrides.Name != "" {
			profile.Name = overrides.Name
		}
		if overrides.Model != "" {
			profile.Model = overrides.Model
		}
		if overrides.Role != "" {
			profile.Role = overrides.Role
		}
		if overrides.Networks != nil {
			if profile.Networks == nil {
				profile.Networks = make(map[string]*entities.NetworkPhaseConfig)
			}
			for k, v := range overrides.Networks {
				profile.Networks[k] = v
			}
		}
		if overrides.EnrollmentNetwork != "" {
			profile.EnrollmentNetwork = overrides.EnrollmentNetwork
		}
		if overrides.PostEnrollmentNetwork != "" {
			profile.PostEnrollmentNetwork = overrides.PostEnrollmentNetwork
		}
		if overrides.FailureNetwork != "" {
			profile.FailureNetwork = overrides.FailureNetwork
		}
		if overrides.PlatformdConfig != nil {
			profile.PlatformdConfig = overrides.PlatformdConfig
		}
		if overrides.MatchRules != nil {
			profile.MatchRules = overrides.MatchRules
		}
		if overrides.WorkloadPCR != 0 {
			profile.WorkloadPCR = overrides.WorkloadPCR
		}
	}

	return profile, nil
}

// deepCopyMatchRules creates a deep copy of ProfileMatchRules using YAML marshal/unmarshal.
func deepCopyMatchRules(src *entities.ProfileMatchRules) (*entities.ProfileMatchRules, error) {
	data, err := yaml.Marshal(src)
	if err != nil {
		return nil, err
	}
	dst := &entities.ProfileMatchRules{}
	if err := yaml.Unmarshal(data, dst); err != nil {
		return nil, err
	}
	return dst, nil
}
