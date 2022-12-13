package controller

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/session"
	"github.com/maximthomas/gortas/pkg/user"
	"github.com/sirupsen/logrus"
)

var (
	privateKey, _ = rsa.GenerateKey(rand.Reader, 1024)
	publicKey     = &privateKey.PublicKey

	privateKeyStr = string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	))

	publicKeyStr = string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PublicKey(publicKey),
		},
	))
	flows = map[string]config.Flow{
		"default": {Modules: []config.Module{
			{
				ID:   "login",
				Type: "login",
			},
		}},
		"register": {Modules: []config.Module{
			{
				ID:   "registration",
				Type: "registration",
				Properties: map[string]interface{}{
					"testProp": "testVal",
					"additionalFields": []map[interface{}]interface{}{{
						"dataStore": "name",
						"prompt":    "Name",
					}},
				},
			},
		}},
		"sso": {Modules: []config.Module{}},
	}

	logger = logrus.New()
	conf   = config.Config{
		Flows: flows,
		UserDataStore: config.UserDataStore{
			Repo: user.NewInMemoryUserRepository(),
		},
		Logger: logger,
		Session: config.Session{
			Type:    "stateless",
			Expires: 60000,
			Jwt: config.SessionJWT{
				Issuer:     "http://gortas",
				PrivateKey: privateKey,
				PublicKey:  publicKey,
			},
			DataStore: config.SessionDataStore{
				Repo: session.NewInMemorySessionRepository(logger),
			},
		},
	}
)
