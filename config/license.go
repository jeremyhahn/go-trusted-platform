package config

type License interface {
	GetOrganizationQuota() int
}

type LicenseStruct struct {
	OrganizationQuota int
}

func (license *LicenseStruct) GetOrganizationQuota() int {
	return license.OrganizationQuota
}
