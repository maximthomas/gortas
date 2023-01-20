package session

import (
	"errors"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/google/uuid"
)

type sessionRepository interface {
	CreateSession(session Session) (Session, error)
	DeleteSession(id string) error
	GetSession(id string) (Session, error)
	UpdateSession(session Session) error
}

type inMemorySessionRepository struct {
	sessions map[string]Session
	logger   logrus.FieldLogger
}

func (sr *inMemorySessionRepository) CreateSession(session Session) (Session, error) {
	if session.ID == "" {
		session.ID = uuid.New().String()
	}
	session.CreatedAt = time.Now()
	sr.sessions[session.ID] = session
	return session, nil
}

func (sr *inMemorySessionRepository) DeleteSession(id string) error {
	if _, ok := sr.sessions[id]; ok {
		delete(sr.sessions, id)
		return nil
	}
	return errors.New("session does not exist")
}

func (sr *inMemorySessionRepository) GetSession(id string) (Session, error) {
	if session, ok := sr.sessions[id]; ok {
		return session, nil
	}
	return Session{}, errors.New("session does not exist")
}

func (sr *inMemorySessionRepository) UpdateSession(session Session) error {
	if _, ok := sr.sessions[session.ID]; ok {
		sr.sessions[session.ID] = session
		return nil
	}
	return errors.New("session does not exist")
}

const cleanupIntervalSeconds = 10

func (sr *inMemorySessionRepository) cleanupExpired() {
	ticker := time.NewTicker(time.Second * cleanupIntervalSeconds)
	defer ticker.Stop()
	for {
		<-ticker.C
		for k := range sr.sessions {
			sess := sr.sessions[k]
			if (sess.CreatedAt.Second() + 60*60*24) < time.Now().Second() {
				sr.logger.Infof("delete session %s due to timeout", sess.ID)
				delete(sr.sessions, k)
			}
		}
	}
}

func newInMemorySessionRepository() sessionRepository {
	repo := &inMemorySessionRepository{
		sessions: make(map[string]Session),
	}

	go repo.cleanupExpired()
	return repo
}
