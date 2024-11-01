package entities

type ACMEIdentifier struct {
	Type  string `yaml:"type" json:"type"`
	Value string `yaml:"value" json:"value"`
}
