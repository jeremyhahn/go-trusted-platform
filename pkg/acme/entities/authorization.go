package entities

const (
	AUTHORIZATION_INDEX_URL = "url"
)

type ACMEAuthorization struct {
	ID         uint64          `yaml:"id" json:"id"`
	Identifier ACMEIdentifier  `yaml:"identifier" json:"identifier"`
	Status     string          `yaml:"status" json:"status"`
	Expires    string          `yaml:"expires" json:"expires"`
	Challenges []ACMEChallenge `yaml:"challenges" json:"challenges"`
	Wildcard   bool            `yaml:"wildcard" json:"wildcard"`
	AccountID  uint64          `yaml:"account-id" json:"account_id"`
	OrderID    uint64
	URL        string `yaml:"url" json:"url"`
}

func (account *ACMEAuthorization) SetEntityID(id uint64) {
	account.ID = id
}

func (account *ACMEAuthorization) EntityID() uint64 {
	return account.ID
}
