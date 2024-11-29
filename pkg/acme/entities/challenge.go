package entities

type ACMEChallenge struct {
	ID              uint64 `yaml:"id" json:"id"`
	Type            string `yaml:"type" json:"type"`
	URL             string `yaml:"url" json:"url"`
	Status          string `yaml:"status" json:"status"`
	Token           string `yaml:"token" json:"token"`
	Validated       string `yaml:"validated" json:"validated,omitempty"`
	Error           *Error `yaml:"error" json:"error,omitempty"`
	AccountID       uint64 `yaml:"account-id" json:"account_id"`
	AuthorizationID uint64 `yaml:"authorization-id" json:"authorization_id"`
}

func (challenge *ACMEChallenge) SetEntityID(id uint64) {
	challenge.ID = id
}

func (challenge *ACMEChallenge) EntityID() uint64 {
	return challenge.ID
}
