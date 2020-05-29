package repo

import (
	"bytes"
	"encoding/json"
	"github.com/maximthomas/gortas/pkg/models"
	"io/ioutil"
	"log"
	"net/http"
)

type RestSessionRepository struct {
	Endpoint string
	client   http.Client
}

func (sr *RestSessionRepository) CreateSession(session models.Session) (models.Session, error) {
	var newSession models.Session
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

	body, err := ioutil.ReadAll(resp.Body)
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

func (sr *RestSessionRepository) DeleteSession(id string) error {
	req, err := http.NewRequest("DELETE", sr.Endpoint+"/"+id, nil)
	if err != nil {
		return err
	}
	_, err = sr.client.Do(req)

	return err
}

func (sr *RestSessionRepository) UpdateSession(id string, session models.Session) error {
	return nil
}
