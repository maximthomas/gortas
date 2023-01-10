package controller

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/session"
)

var (
	privateKey, _ = rsa.GenerateKey(rand.Reader, 1024)

	privateKeyStr = string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
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

	conf = config.Config{
		Flows: flows,
		Session: session.Config{
			Type:    "stateless",
			Expires: 60000,
			Jwt: session.JWT{
				Issuer: "http://gortas",
			},
		},
	}
)
