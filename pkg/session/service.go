package session

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/rand"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
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

func (ss *SessionService) CreateSession(session Session) (Session, error) {
	return ss.repo.CreateSession(session)
}

func (ss *SessionService) DeleteSession(id string) error {
	return ss.repo.DeleteSession(id)
}

func (ss *SessionService) GetSession(id string) (Session, error) {
	return ss.repo.GetSession(id)
}

func (ss *SessionService) UpdateSession(session Session) error {
	return ss.repo.UpdateSession(session)
}

func (ss *SessionService) ConvertSessionToJwt(sessID string) (string, error) {
	sess, err := ss.GetSession(sessID)
	if err != nil {
		return "", err
	}

	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	exp := time.Second * time.Duration(rand.Intn(ss.expires))
	claims["exp"] = time.Now().Add(exp).Unix()
	claims["jti"] = ss.jwt.PrivateKeyID
	claims["iat"] = time.Now().Unix()
	claims["iss"] = ss.jwt.Issuer
	claims["sub"] = sess.GetUserID()
	claims["props"] = sess.Properties
	token.Header["jks"] = ss.jwt.PrivateKeyID
	return token.SignedString(ss.jwt.PrivateKey)
}

func (ss *SessionService) CreateUserSession(userID string) (sessID string, err error) {
	var sessionID string
	u, userExists := user.GetUserService().GetUser(userID)
	if ss.sessionType == "stateless" {
		token := jwt.New(jwt.SigningMethodRS256)
		claims := token.Claims.(jwt.MapClaims)
		exp := time.Second * time.Duration(rand.Intn(ss.expires))
		claims["exp"] = time.Now().Add(exp).Unix()
		claims["jti"] = ss.jwt.PrivateKeyID
		claims["iat"] = time.Now().Unix()
		claims["iss"] = ss.jwt.Issuer
		claims["sub"] = userID
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
				"sub":    userID,
			},
		}
		if userExists {
			for k, v := range u.Properties {
				newSession.Properties[k] = v
			}
		}

		newSession, err = ss.CreateSession(newSession)
		if err != nil {
			return sessID, err
		}
	}
	return sessionID, nil
}

func (ss *SessionService) GetSessionData(sessionID string) (sess map[string]interface{}, err error) {
	sess = make(map[string]interface{})

	if ss.sessionType == "stateless" {
		publicKey := ss.jwt.PublicKey
		claims := jwt.MapClaims{}
		_, err = jwt.ParseWithClaims(sessionID, claims, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			return sess, err
		}
		sess = claims
	} else {
		var statefulSession Session
		statefulSession, err = ss.GetSession(sessionID)
		if statefulSession.GetUserID() == "" {
			return sess, errors.New("user session  not found")
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

func (ss *SessionService) GetJwtPublicKey() *rsa.PublicKey {
	return ss.jwt.PublicKey
}

var ss SessionService

func InitSessionService(sc *SessionConfig) error {
	newSs, err := newSessionServce(sc)
	if err != nil {
		return err
	}
	ss = newSs
	return nil
}

func newSessionServce(sc *SessionConfig) (ss SessionService, err error) {
	token := sc.Jwt

	if token.PrivateKeyPem != "" {
		var privateKey *rsa.PrivateKey
		privateKeyBlock, _ := pem.Decode([]byte(token.PrivateKeyPem))
		privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
		if err != nil {
			return ss, err
		}
		ss.jwt.PrivateKey = privateKey
		ss.jwt.PublicKey = &privateKey.PublicKey
		ss.jwt.PrivateKeyID = uuid.New().String()
		ss.jwt.Issuer = token.Issuer
	}

	if sc.DataStore.Type == "mongo" {
		prop := sc.DataStore.Properties
		params := make(map[string]string)
		err = mapstructure.Decode(&prop, &params)
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

func GetSessionService() *SessionService {
	return &ss
}

func SetSessionService(newSs *SessionService) {
	ss = *newSs
}
