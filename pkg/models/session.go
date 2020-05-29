package models

import "time"

//SessionDataStore struct represents session object from session service
type Session struct {
	ID         string            `json:"id,omitempty"`
	CreatedAt  time.Time         `json:"createdat,omitempty" bson:"createdAt"`
	Properties map[string]string `json:"properties,omitempty"`
}
