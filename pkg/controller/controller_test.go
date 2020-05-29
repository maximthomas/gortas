package controller

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/repo"
	"github.com/prometheus/common/log"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var privateKey, _ = rsa.GenerateKey(rand.Reader, 1024)
var publicKey = &privateKey.PublicKey

var privateKeyStr = string(pem.EncodeToMemory(
	&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	},
))

var publicKeyStr = string(pem.EncodeToMemory(
	&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	},
))

var (
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

				AuthChains: map[string]config.AuthChain{
					"default": {Modules: []config.ChainModule{
						{
							ID: "login",
						},
					}},
					"register": {Modules: []config.ChainModule{
						{
							ID: "registration",
							Properties: map[string]interface{}{
								"testProp": "testVal",
							},
						},
					}},
					"sso": {Modules: []config.ChainModule{}},
				},
				UserDataStore: config.UserDataStore{
					Repo: repo.NewInMemoryUserRepository(),
				},
			},
		},
	}

	conf = config.Config{
		Authentication: ac,
		Logger:         logrus.New(),
		Session: config.Session{
			Type:    "stateless",
			Expires: 60000,
			Jwt: config.SessionJWT{
				Issuer:     "http://gortas",
				PrivateKey: privateKey,
				PublicKey:  publicKey,
			},
			DataStore: config.SessionDataStore{
				Repo: repo.NewInMemorySessionRepository(),
			},
		},
	}

	lc = NewLoginController(conf)
)

func TestControllerLoginByRealmChain(t *testing.T) {
	var tests = []struct {
		expectedStatus int
		realmID        string
		authChainID    string
	}{
		{404, "clients", "users"},
		{404, "staff", "users"},
		{200, "staff", "default"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt), func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest("GET", "/login", nil)

			lc.Login(tt.realmID, tt.authChainID, c)
			assert.Equal(t, tt.expectedStatus, recorder.Result().StatusCode)
			log.Info(recorder.Body.String())
		})
	}
}

func TestLoginPassword(t *testing.T) {
	t.Run("Test auth password", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		bodyStr := `{"callbacks":
[{"name":"login","type":"text","value":"user1"},{"name":"password","type":"password","value":"pass"}]}`
		body := bytes.NewBufferString(bodyStr)
		c.Request = httptest.NewRequest("POST", "/login", body)

		lc.Login("staff", "default", c)
		assert.Equal(t, 200, recorder.Result().StatusCode)
		log.Info(recorder.Body.String())
	})
}

func TestGetSessionState(t *testing.T) {
	t.Run("Test Get New SessionDataStore State", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", "/login", nil)
		lls := lc.getLoginSessionState(ac.Realms["staff"].AuthChains["default"], ac.Realms["staff"], c)
		assert.Equal(t, 1, len(lls.Modules))
	})

	t.Run("Test Get Existing State Login", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", "/login", nil)
		lss := lc.getLoginSessionState(ac.Realms["staff"].AuthChains["default"], ac.Realms["staff"], c)
		assert.Equal(t, 1, len(lss.Modules))
		lss.SharedState["key"] = "value"
		lss.UserId = "user1"
		err := lc.updateLoginSessionState(lss)
		assert.Nil(t, err)

		cSecond, _ := gin.CreateTestContext(recorder)
		authCookie := &http.Cookie{
			Name:  auth.AuthCookieName,
			Value: lss.SessionId,
		}
		cSecond.Request = httptest.NewRequest("POST", "/login", nil)
		cSecond.Request.AddCookie(authCookie)
		lssUpdated := lc.getLoginSessionState(ac.Realms["staff"].AuthChains["default"], ac.Realms["staff"], cSecond)
		assert.Equal(t, "value", lssUpdated.SharedState["key"])
		assert.Equal(t, "user1", lssUpdated.UserId)
	})

	t.Run("Test Get Existing State Register", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", "/login", nil)
		lss := lc.getLoginSessionState(ac.Realms["staff"].AuthChains["register"], ac.Realms["staff"], c)
		assert.Equal(t, 2, len(lss.Modules[0].Properties))
		assert.Equal(t, 1, len(lss.Modules))
		lss.SharedState["key"] = "value"
		lss.UserId = "user1"
		err := lc.updateLoginSessionState(lss)
		assert.NoError(t, err)

		cSecond, _ := gin.CreateTestContext(recorder)
		authCookie := &http.Cookie{
			Name:  auth.AuthCookieName,
			Value: lss.SessionId,
		}
		cSecond.Request = httptest.NewRequest("POST", "/login", nil)
		cSecond.Request.AddCookie(authCookie)
		lssUpdated := lc.getLoginSessionState(ac.Realms["staff"].AuthChains["register"], ac.Realms["staff"], cSecond)
		assert.Equal(t, 2, len(lssUpdated.Modules[0].Properties))
		assert.Equal(t, "value", lssUpdated.SharedState["key"])
		assert.Equal(t, "user1", lssUpdated.UserId)
	})
}

func TestJWT(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	// Create the Claims
	_ = &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		Issuer:    "test",
	}

	token := jwt.New(jwt.SigningMethodRS256)
	claims2 := token.Claims.(jwt.MapClaims)

	claims2["exp"] = time.Now().Add(time.Hour * 72).Unix()
	token.Header["jks"] = "test"
	ss, _ := token.SignedString(privateKey)
	fmt.Println(ss)

	pemdata := string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	))

	pemDataString := string(pemdata)
	fmt.Println(pemDataString)

}
