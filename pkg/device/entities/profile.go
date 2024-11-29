package entities

type DeviceProfile struct {
	ID       uint64 `yaml:"id" json:"id"`
	Model    string `yaml:"model" json:"model"`
	EventLog []byte `yaml:"eventLog" json:"eventLog"`
}

func (dp *DeviceProfile) EntityID() uint64 {
	return dp.ID
}

func (dp *DeviceProfile) SetEntityID(id uint64) {
	dp.ID = id
}
