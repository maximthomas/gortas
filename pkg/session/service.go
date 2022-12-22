package session

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/rand"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/maximthomas/gortas/pkg/user"
	"github.com/mitchellh/mapstructure"
)

type SessionService struct {
	repo        sessionRepository
	sessionType string
	jwt         Jwt
	expires     int
}

type Jwt struct {
	PrivateKeyID string
	Issuer       string
	PrivateKey   *rsa.PrivateKey
	PublicKey    *rsa.PublicKey
}

func (ss SessionService) CreateSession(session Session) (Session, error) {
	return ss.repo.CreateSession(session)
}

func (ss SessionService) DeleteSession(id string) error {
	return ss.repo.DeleteSession(id)
}

func (ss SessionService) GetSession(id string) (Session, error) {
	return ss.repo.GetSession(id)
}

func (ss SessionService) UpdateSession(session Session) error {
	return ss.repo.UpdateSession(session)
}

func (ss SessionService) CreateUserSession(userId string) (sessId string, err error) {
	var sessionID string
	u, userExists := user.GetUserService().GetUser(userId)
	if ss.sessionType == "stateless" {
		token := jwt.New(jwt.SigningMethodRS256)
		claims := token.Claims.(jwt.MapClaims)
		exp := time.Second * time.Duration(rand.Intn(ss.expires))
		claims["exp"] = time.Now().Add(exp).Unix()
		claims["jti"] = ss.jwt.PrivateKeyID
		claims["iat"] = time.Now().Unix()
		claims["iss"] = ss.jwt.Issuer
		claims["sub"] = userId
		if userExists {
			claims["props"] = u.Properties
		}

		token.Header["jks"] = ss.jwt.PrivateKeyID
		ss, _ := token.SignedString(ss.jwt.PrivateKey)
		sessionID = ss
	} else {
		sessionID = uuid.New().String()
		newSession := Session{
			ID: sessionID,
			Properties: map[string]string{
				"userId": u.ID,
				"sub":    userId,
			},
		}
		if userExists {
			for k, v := range u.Properties {
				newSession.Properties[k] = v
			}
		}

		newSession, err = ss.CreateSession(newSession)
		if err != nil {
			return sessId, err
		}
	}
	return sessionID, nil
}

func (ss SessionService) GetSessionData(sessionId string) (sess map[string]interface{}, err error) {
	sess = make(map[string]interface{})

	if ss.sessionType == "stateless" {
		publicKey := ss.jwt.PublicKey
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(sessionId, claims, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			return sess, err
		}
		sess = claims
	} else {
		statefulSession, err := ss.GetSession(sessionId)
		if statefulSession.GetUserID() == "" {
			return sess, errors.New("User session  not found")
		}
		if err != nil {
			return sess, err
		}
		sess["id"] = statefulSession.ID
		sess["created"] = statefulSession.CreatedAt
		sess["properties"] = statefulSession.Properties
	}
	return sess, err
}

func (ss SessionService) GetJwtPublicKey() *rsa.PublicKey {
	return ss.jwt.PublicKey
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
		ss.jwt.PrivateKey = privateKey
		ss.jwt.PublicKey = &privateKey.PublicKey
		ss.jwt.PrivateKeyID = uuid.New().String()
		ss.jwt.Issuer = jwt.Issuer
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
		ss.repo, err = NewMongoSessionRepository(url, db, col)
		if err != nil {
			return ss, err
		}
	} else {
		ss.repo = NewInMemorySessionRepository()
	}
	ss.sessionType = sc.Type
	ss.expires = sc.Expires
	return ss, err
}

func GetSessionService() SessionService {
	return ss
}

func SetSessionService(newSs SessionService) {
	ss = newSs
}
