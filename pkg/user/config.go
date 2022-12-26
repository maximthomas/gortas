package user

type UserConfig struct {
	Type       string                 `yaml:"type"`
	Properties map[string]interface{} `yaml:"properties,omitempty"`
}
