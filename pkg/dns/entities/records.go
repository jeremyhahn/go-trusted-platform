package entities

type RecordSet struct {
	ARecords      []*ARecord      `yaml:"a,omitempty" json:"a,omitempty" mapstructure:"a,omitempty"`
	AAAARecords   []*AAAARecord   `yaml:"aaaa,omitempty" json:"aaaa,omitempty" mapstructure:"aaaa,omitempty"`
	CNAMERecords  []*CNAMERecord  `yaml:"cname,omitempty" json:"cname,omitempty" mapstructure:"cname,omitempty"`
	DNSKEYRecords []*DNSKEYRecord `yaml:"key,omitempty" json:"key,omitempty" mapstructure:"key,omitempty"`
	DSRecords     []*DSRecord     `yaml:"ds,omitempty" json:"ds,omitempty" mapstructure:"ds,omitempty"`
	MXRecords     []*MXRecord     `yaml:"mx,omitempty" json:"mx,omitempty" mapstructure:"mx,omitempty"`
	NSRecords     []*NSRecord     `yaml:"ns,omitempty" json:"ns,omitempty" mapstructure:"ns,omitempty"`
	RRSIGRecords  []*RRSIGRecord  `yaml:"rrsig,omitempty" json:"rrsig,omitempty" mapstructure:"rrsig,omitempty"`
	SOARecord     SOARecord       `yaml:"soa,omitempty" json:"soa,omitempty" mapstructure:"soa,omitempty"`
	SRVRecords    []*SRVRecord    `yaml:"srv,omitempty" json:"srv,omitempty" mapstructure:"srv,omitempty"`
	TXTRecords    []*TXTRecord    `yaml:"txt,omitempty" json:"txt,omitempty" mapstructure:"txt,omitempty"`
}

type ARecord struct {
	Name  string `yaml:"name" json:"name" mapstructure:"name"`
	TTL   uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Value string `yaml:"value" json:"value" mapstructure:"value"`
}

type AAAARecord struct {
	Name  string `yaml:"name" json:"name" mapstructure:"name"`
	TTL   uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Value string `yaml:"value" json:"value" mapstructure:"value"`
}

type CNAMERecord struct {
	Name  string `yaml:"name" json:"name" mapstructure:"name"`
	TTL   uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Value string `yaml:"value" json:"value" mapstructure:"value"`
}

type DNSKEYRecord struct {
	Algorithm uint8  `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Flags     uint16 `yaml:"flags" json:"flags" mapstructure:"flags"`
	ID        uint64 `yaml:"id" json:"id" mapstructure:"id"`
	Key       string `yaml:"key" json:"key" mapstructure:"key"`
	Name      string `yaml:"name" json:"name" mapstructure:"name"`
	Protocol  uint8  `yaml:"protocol" json:"protocol" mapstructure:"protocol"`
	TTL       uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
}

type DSRecord struct {
	Algorithm  uint8  `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Digest     string `yaml:"digest" json:"digest" mapstructure:"digest"`
	DigestType uint8  `yaml:"digest_type" json:"digest_type" mapstructure:"digest_type"`
	ID         uint64 `yaml:"id" json:"id" mapstructure:"id"`
	KeyTag     uint16 `yaml:"key-tag" json:"key_tag" mapstructure:"key_tag"`
	Name       string `yaml:"name" json:"name" mapstructure:"name"`
	TTL        uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
}

type MXRecord struct {
	Name     string `yaml:"name" json:"name" mapstructure:"name"`
	Priority uint16 `yaml:"priority" json:"priority" mapstructure:"priority"`
	TTL      uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Value    string `yaml:"value" json:"value" mapstructure:"value"`
}

type NSRecord struct {
	Name  string `yaml:"name" json:"name" mapstructure:"name"`
	TTL   uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Value string `yaml:"value" json:"value" mapstructure:"value"`
}

type RRSIGRecord struct {
	Algorithm   uint8  `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Expiration  string `yaml:"expiration" json:"expiration" mapstructure:"expiration"`
	Inception   string `yaml:"inception" json:"inception" mapstructure:"inception"`
	KeyTag      uint16 `yaml:"key-tag" json:"key_tag" mapstructure:"key_tag"`
	Labels      uint8  `yaml:"labels" json:"labels" mapstructure:"labels"`
	OriginalTTL uint32 `yaml:"original-ttl,omitempty" json:"original_ttl,omitempty" mapstructure:"original_ttl,omitempty"`
	Signature   string `yaml:"signature" json:"signature" mapstructure:"signature"`
	SignerName  string `yaml:"signer" json:"signer" mapstructure:"signer"`
	TypeCovered string `yaml:"type-covered" json:"type_covered" mapstructure:"type_covered"`
}

type SOARecord struct {
	Expire     uint32 `yaml:"expire" json:"expire" mapstructure:"expire"`
	MName      string `yaml:"mname" json:"mname" mapstructure:"mname"`
	MinimumTTL uint32 `yaml:"min-ttl,omitempty" json:"min_ttl,omitempty" mapstructure:"min_ttl,omitempty"`
	Name       string `yaml:"name" json:"name" mapstructure:"name"`
	RName      string `yaml:"rname" json:"rname" mapstructure:"rname"`
	Refresh    uint32 `yaml:"refresh" json:"refresh" mapstructure:"refresh"`
	Retry      uint32 `yaml:"retry" json:"retry" mapstructure:"retry"`
	Serial     uint32 `yaml:"serial" json:"serial" mapstructure:"serial"`
	TTL        uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
}

type SRVRecord struct {
	Name     string `yaml:"name" json:"name" mapstructure:"name"`
	Port     uint16 `yaml:"port" json:"port" mapstructure:"port"`
	Priority uint16 `yaml:"priority" json:"priority" mapstructure:"priority"`
	Target   string `yaml:"target" json:"target" mapstructure:"target"`
	TTL      uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Weight   uint16 `yaml:"weight" json:"weight" mapstructure:"weight"`
}

type TXTRecord struct {
	Name  string `yaml:"name" json:"name" mapstructure:"name"`
	TTL   uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Value string `yaml:"value" json:"value" mapstructure:"value"`
}
