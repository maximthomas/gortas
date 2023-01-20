package session

type Config struct {
	Type      string    `yaml:"type"`
	Expires   int       `yaml:"expires"`
	Jwt       JWT       `yaml:"jwt,omitempty"`
	DataStore DataStore `yaml:"dataStore,omitempty"`
}

type JWT struct {
	Issuer        string `yaml:"issuer"`
	PrivateKeyPem string `yml:"privateKeyPem"`
}

type DataStore struct {
	Type       string
	Properties map[string]string
}
