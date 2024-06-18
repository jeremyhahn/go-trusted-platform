package config

type Server struct {
	ID             uint64
	IpAddress      string
	Hostname       string
	License        *LicenseStruct `yaml:"license" json:"license" mapstructure:"license"`
	ServiceRefs    []uint64       `yaml:"services" json:"services" mapstructure:"services"`
	KeyValueEntity `sql:"-" gorm:"-" yaml:"-" json:"-"`
}

func NewServer() *Server {
	return &Server{
		ServiceRefs: make([]uint64, 0)}
}

func (server *Server) SetID(id uint64) {
	server.ID = id
}

func (server *Server) Identifier() uint64 {
	return server.ID
}

func (server *Server) GetLicense() *LicenseStruct {
	return server.License
}

func (server *Server) SetLicense(license *LicenseStruct) {
	server.License = license
}

func (server *Server) SetServiceRefs(refs []uint64) {
	server.ServiceRefs = refs
}

func (server *Server) GetServiceRefs() []uint64 {
	return server.ServiceRefs
}

func (server *Server) AddServiceRef(serviceID uint64) {
	server.ServiceRefs = append(server.ServiceRefs, serviceID)
}

func (server *Server) RemoveServiceRef(serviceID uint64) {
	refs := make([]uint64, 0)
	for _, ref := range server.ServiceRefs {
		if ref == serviceID {
			continue
		}
		refs = append(refs, ref)
	}
	server.ServiceRefs = refs
}

func (server *Server) SetFarmRefs(refs []uint64) {
	server.ServiceRefs = refs
}
