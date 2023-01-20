package user

type Config struct {
	Type       string                 `yaml:"type"`
	Properties map[string]interface{} `yaml:"properties,omitempty"`
}
