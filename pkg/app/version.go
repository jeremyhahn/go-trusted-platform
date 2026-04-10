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

package app

var (
	Name,
	Repository,
	Package,
	Version,
	BuildDate,
	BuildUser,
	GitBranch,
	GitTag,
	GitHash,
	Image string
)

type AppVersion struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
	Package    string `json:"package"`
	Version    string `json:"version"`
	GitBranch  string `json:"gitBranch"`
	GitTag     string `json:"gitTag"`
	GitHash    string `json:"gitHash"`
	BuildDate  string `json:"buildDate"`
	BuildUser  string `json:"buildUser"`
}

func GetVersion() *AppVersion {
	return &AppVersion{
		Name:       Name,
		Repository: Repository,
		Package:    Package,
		Version:    Version,
		GitBranch:  GitBranch,
		GitTag:     GitTag,
		GitHash:    GitHash,
		BuildDate:  BuildDate,
		BuildUser:  BuildUser}
}
