package session

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
)

type restSessionRepository struct {
	Endpoint string
	client   http.Client
}

func (sr *restSessionRepository) CreateSession(session Session) (Session, error) {
	var newSession Session
	sessBytes, err := json.Marshal(session)
	if err != nil {
		return newSession, err
	}
	buf := bytes.NewBuffer(sessBytes)

	resp, err := sr.client.Post(sr.Endpoint, "application/json", buf)
	if err != nil {
		log.Printf("error creating session: %v", err)
		return newSession, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error creating session: %v", err)
		return newSession, err
	}

	err = json.Unmarshal(body, &newSession)
	if err != nil {
		log.Printf("error creating session: %v", err)
		return newSession, err
	}
	log.Printf("created new session: %v", newSession)
	return newSession, err
}

func (sr *restSessionRepository) DeleteSession(id string) error {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, sr.Endpoint+"/"+id, http.NoBody)
	if err != nil {
		return err
	}

	resp, err := sr.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return err
}

func (sr *restSessionRepository) UpdateSession(id string, session Session) error {
	return nil
}
