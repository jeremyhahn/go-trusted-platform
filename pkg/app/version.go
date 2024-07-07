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
