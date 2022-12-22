package session

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"
)

type SessionService struct {
	Repo SessionRepository
	Type string
	Jwt  JWT
}

type JWT struct {
	PrivateKeyID string
	Issuer       string
	PrivateKey   *rsa.PrivateKey
	PublicKey    *rsa.PublicKey
}

var ss SessionService

func InitSessionService(sc SessionConfig) error {
	newSs, err := newSessionServce(sc)
	if err != nil {
		return err
	}
	ss = newSs
	return nil
}

func newSessionServce(sc SessionConfig) (ss SessionService, err error) {
	if sc.Type == "stateless" {
		jwt := &sc.Jwt
		privateKeyBlock, _ := pem.Decode([]byte(jwt.PrivateKeyPem))
		privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
		if err != nil {
			return ss, err
		}
		ss.Jwt.PrivateKey = privateKey
		ss.Jwt.PublicKey = &privateKey.PublicKey
		ss.Jwt.PrivateKeyID = uuid.New().String()
		ss.Jwt.Issuer = jwt.Issuer
	}

	if sc.DataStore.Type == "mongo" {
		prop := sc.DataStore.Properties
		params := make(map[string]string)
		err := mapstructure.Decode(&prop, &params)
		if err != nil {
			return ss, err
		}
		url := params["url"]
		db := params["database"]
		col := params["collection"]
		ss.Repo, err = NewMongoSessionRepository(url, db, col)
		if err != nil {
			return ss, err
		}
	} else {
		ss.Repo = NewInMemorySessionRepository()
	}
	return ss, err
}

func GetSessionService() SessionService {
	return ss
}

func SetSessionService(newSs SessionService) {
	ss = newSs
}
