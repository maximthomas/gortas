package models

type User struct {
	ID         string            `json:"id,omitempty"`
	Realm      string            `json:"realm,omitempty"`
	Roles      []string          `json:"roles,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type Password struct {
	Password string `json:"password,omitempty"`
}

type ValidatePasswordResult struct {
	Valid bool `json:"valid,omitempty"`
}
