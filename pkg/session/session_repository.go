package session

import (
	"errors"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/google/uuid"
)

type SessionRepository interface {
	CreateSession(session Session) (Session, error)
	DeleteSession(id string) error
	GetSession(id string) (Session, error)
	UpdateSession(session Session) error
}

type InMemorySessionRepository struct {
	sessions map[string]Session
	logger   logrus.FieldLogger
}

func (sr *InMemorySessionRepository) CreateSession(session Session) (Session, error) {
	if session.ID == "" {
		session.ID = uuid.New().String()
	}
	session.CreatedAt = time.Now()
	sr.sessions[session.ID] = session
	return session, nil
}

func (sr *InMemorySessionRepository) DeleteSession(id string) error {
	if _, ok := sr.sessions[id]; ok {
		delete(sr.sessions, id)
		return nil
	} else {
		return errors.New("session does not exist")
	}
}

func (sr *InMemorySessionRepository) GetSession(id string) (Session, error) {
	if session, ok := sr.sessions[id]; ok {
		return session, nil
	} else {
		return Session{}, errors.New("session does not exist")
	}
}

func (sr *InMemorySessionRepository) UpdateSession(session Session) error {
	if _, ok := sr.sessions[session.ID]; ok {
		sr.sessions[session.ID] = session
		return nil
	} else {
		return errors.New("session does not exist")
	}
}

func (sr *InMemorySessionRepository) cleanupExpired() {
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	for {
		_ = <-ticker.C
		for k := range sr.sessions {
			sess := sr.sessions[k]
			if (sess.CreatedAt.Second() + 60*60*24) < time.Now().Second() {
				sr.logger.Infof("delete session %s due to timeout", sess.ID)
				delete(sr.sessions, k)
			}
		}
	}
}

func NewInMemorySessionRepository(logger *logrus.Logger) SessionRepository {
	if logger == nil {
		logger = logrus.New()
	}
	repo := &InMemorySessionRepository{
		sessions: make(map[string]Session),
		logger:   logger.WithField("module", "InMemorySessionRepository"),
	}

	go repo.cleanupExpired()
	return repo
}
