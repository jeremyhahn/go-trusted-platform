package config

type License interface {
	Quota() int
}

type LicenseStruct struct {
	quota int
}

func (license *LicenseStruct) Quota() int {
	return license.quota
}
