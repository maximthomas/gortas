package session

type SessionConfig struct {
	Type      string           `yaml:"type"`
	Expires   int              `yaml:"expires"`
	Jwt       SessionJWT       `yaml:"jwt,omitempty"`
	DataStore SessionDataStore `yaml:"dataStore,omitempty"`
}

type SessionJWT struct {
	Issuer        string `yaml:"issuer"`
	PrivateKeyPem string `yml:"privateKeyPem"`
}

type SessionDataStore struct {
	Type       string
	Properties map[string]string
}
