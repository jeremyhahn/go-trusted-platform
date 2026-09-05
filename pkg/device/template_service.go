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
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
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
		return nil, &WrappedError{Msg: "failed to get template DAO", Err: err}
	}

	profileDAO, err := ds.ProfileDAO()
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get profile DAO", Err: err}
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
		return &WrappedError{Msg: "failed to save template", Err: err}
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
		return nil, &WrappedError{Msg: "failed to get template", Err: err}
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
		return &WrappedError{Msg: "failed to delete template", Err: err}
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
		return &WrappedError{Msg: "failed to get template for update", Err: err}
	}

	template.UpdatedAt = time.Now()

	if err := s.templateDAO.Save(ctx, template); err != nil {
		return &WrappedError{Msg: "failed to update template", Err: err}
	}

	return nil
}

// Count returns the total number of device templates.
func (s *TemplateService) Count(ctx context.Context) (int, error) {
	count, err := s.templateDAO.Count(ctx)
	if err != nil {
		return 0, &WrappedError{Msg: "failed to count templates", Err: err}
	}
	return count, nil
}

// Page retrieves a paginated list of device templates.
func (s *TemplateService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceTemplate], error) {
	result, err := s.templateDAO.Page(ctx, query)
	if err != nil {
		return datastore.PageResult[*entities.DeviceTemplate]{}, &WrappedError{Msg: "failed to page templates", Err: err}
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
		return nil, &WrappedError{Msg: "failed to find template by name", Err: err}
	}

	return template, nil
}

// ToProfile deep-copies the template config into a new DeviceProfile with optional overrides.
// It does NOT save the profile -- the caller is responsible for saving.
//
// The template's Config (raw YAML bytes) is the full base platform configuration.
// When configOverrides are provided, they are deep-merged onto the template config.
// The merged result is stored in both profile.Config (for HandleGetConfig delivery)
// and profile.PlatformdConfig.Inline (for backward compatibility).
func (s *TemplateService) ToProfile(
	ctx context.Context,
	templateID uint64,
	overrides *entities.DeviceProfile,
) (*entities.DeviceProfile, error) {

	return s.ToProfileWithConfigOverrides(ctx, templateID, overrides, nil)
}

// ToProfileWithConfigOverrides creates a profile from a template, applying both
// structural overrides (name, role, networks, etc.) and config-level overrides
// (deep-merged into the template's platform YAML config).
func (s *TemplateService) ToProfileWithConfigOverrides(
	ctx context.Context,
	templateID uint64,
	overrides *entities.DeviceProfile,
	configOverrides map[string]interface{},
) (*entities.DeviceProfile, error) {

	if templateID == 0 {
		return nil, ErrInvalidTemplateID{}
	}

	template, err := s.templateDAO.Get(ctx, templateID)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get template for profile conversion", Err: err}
	}

	profile := &entities.DeviceProfile{
		TenantID: template.TenantID,
		Role:     template.Role,
	}

	// Deep-copy the template config into a PlatformdConfigRef and profile.Config.
	// The template stores raw YAML bytes; unmarshal into a generic map
	// for the inline config to avoid import cycles with the app package.
	if len(template.Config) > 0 {
		var configMap map[string]interface{}
		if err := yaml.Unmarshal(template.Config, &configMap); err != nil {
			return nil, &WrappedError{Msg: "failed to unmarshal template config", Err: err}
		}

		// Apply config-level overrides (e.g. hostname, IP) via deep merge.
		if len(configOverrides) > 0 {
			config.DeepMergeMaps(configMap, configOverrides)
		}

		profile.PlatformdConfig = &entities.PlatformdConfigRef{
			ConfigType: "inline",
			Inline:     configMap,
		}

		// Store the full merged config in profile.Config so HandleGetConfig
		// can return it directly without needing to re-merge.
		profile.Config = configMap
	}

	// Deep-copy match rules via YAML round-trip
	if template.MatchRules != nil {
		rulesCopy, err := deepCopyMatchRules(template.MatchRules)
		if err != nil {
			return nil, &WrappedError{Msg: "failed to deep copy match rules", Err: err}
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
		// Identity binding and the profile-level zone travel with the same
		// override body as the networks; until #378 they were dropped here,
		// so a caller that set them saw a 201 and a profile without them.
		if overrides.EKSerial != "" {
			profile.EKSerial = overrides.EKSerial
		}
		if overrides.MACAddress != "" {
			profile.MACAddress = overrides.MACAddress
		}
		if overrides.Zone != "" {
			profile.Zone = overrides.Zone
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

// NewRoleTemplate builds the template the bootstrap seeder uploads for a
// node role: the canonical role spelling is the template's name and role, the
// config is stored verbatim, and the ID is derived from that name so
// re-seeding the same role — under any accepted spelling — updates the same
// record. A role outside the DeviceRole vocabulary is
// entities.ErrUnknownDeviceRole.
func NewRoleTemplate(role string, config []byte) (*entities.DeviceTemplate, error) {
	parsed, err := entities.ParseDeviceRole(role)
	if err != nil {
		return nil, err
	}
	name := string(parsed)
	return &entities.DeviceTemplate{
		ID:     util.NewID([]byte(name)),
		Name:   name,
		Role:   parsed,
		Config: config,
	}, nil
}
