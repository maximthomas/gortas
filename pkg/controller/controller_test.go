package controller

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/repo"
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
	ac = config.Authentication{
		Realms: map[string]config.Realm{
			"staff": {
				Modules: map[string]config.Module{
					"login": {Type: "login"},
					"registration": {
						Type: "registration",
						Properties: map[string]interface{}{
							"additionalFields": []map[interface{}]interface{}{{
								"dataStore": "name",
								"prompt":    "Name",
							}},
						},
					},
				},

				AuthFlows: map[string]config.AuthFlow{
					"default": {Modules: []config.FlowModule{
						{
							ID: "login",
						},
					}},
					"register": {Modules: []config.FlowModule{
						{
							ID: "registration",
							Properties: map[string]interface{}{
								"testProp": "testVal",
							},
						},
					}},
					"sso": {Modules: []config.FlowModule{}},
				},
				UserDataStore: config.UserDataStore{
					Repo: repo.NewInMemoryUserRepository(),
				},
			},
		},
	}
	logger = logrus.New()
	conf   = config.Config{
		Authentication: ac,
		Logger:         logger,
		Session: config.Session{
			Type:    "stateless",
			Expires: 60000,
			Jwt: config.SessionJWT{
				Issuer:     "http://gortas",
				PrivateKey: privateKey,
				PublicKey:  publicKey,
			},
			DataStore: config.SessionDataStore{
				Repo: repo.NewInMemorySessionRepository(logger),
			},
		},
	}
)
