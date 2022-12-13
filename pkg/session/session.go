package session

import "time"

// SessionDataStore struct represents session object from session service
type Session struct {
	ID         string            `json:"id,omitempty"`
	CreatedAt  time.Time         `json:"createdat,omitempty" bson:"createdAt"`
	Properties map[string]string `json:"properties,omitempty"`
}

func (s *Session) GetUserID() string {
	userID, ok := s.Properties["sub"]
	if !ok {
		return ""
	}
	return userID
}

func (s *Session) SetUserID(userID string) {
	s.Properties["sub"] = userID
}

func (s *Session) GetRealm() string {
	realm, ok := s.Properties["realm"]
	if !ok {
		return ""
	}
	return realm
}
