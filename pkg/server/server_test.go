package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/dgrijalva/jwt-go"

	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/models"
	"github.com/maximthomas/gortas/pkg/repo"
	"github.com/prometheus/common/log"
	"github.com/stretchr/testify/assert"
)

var privateKey, _ = rsa.GenerateKey(rand.Reader, 1024)
var publicKey = &privateKey.PublicKey
var ur = repo.NewInMemoryUserRepository()
var (
	authConf = config.Authentication{
		Realms: map[string]config.Realm{
			"staff": {
				Modules: map[string]config.Module{
					"login":    {Type: "login"},
					"kerberos": {Type: "kerberos"},
					"qr":       {Type: "qr"},
				},
				AuthChains: map[string]config.AuthChain{
					"default": {Modules: []config.ChainModule{
						{
							ID: "login",
						},
					}},
					"kerberos": {Modules: []config.ChainModule{
						{
							ID: "kerberos",
						},
					}},
					"qr": {Modules: []config.ChainModule{
						{
							ID: "qr",
						},
					}},
				},
				UserDataStore: config.UserDataStore{
					Repo: ur,
				},
			},
		},
	}
	logger = logrus.New()
	conf   = config.Config{
		Authentication: authConf,
		Logger:         logger,
		Session: config.Session{
			Type:    "stateless",
			Expires: 60000,
			Jwt: config.SessionJWT{
				Issuer:       "http://gortas",
				PrivateKey:   privateKey,
				PublicKey:    publicKey,
				PrivateKeyID: "dummy",
			},
			DataStore: config.SessionDataStore{Repo: repo.NewInMemorySessionRepository(logger)},
		},
	}
	router = setupRouter(conf)
)

func TestSetupRouter(t *testing.T) {
	assert.Equal(t, 6, len(router.Routes()))
}

const target = "http://localhost/gortas/v1/login/staff/default"

func TestLogin(t *testing.T) {
	t.Run("Test not existing realm", func(t *testing.T) {
		request := httptest.NewRequest("GET", "http://localhost/gortas/v1/login/staff/bad", nil)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		assert.Equal(t, 404, recorder.Result().StatusCode)
		var respJson = make(map[string]interface{})
		err := json.Unmarshal([]byte(recorder.Body.String()), &respJson)
		assert.NoError(t, err)
		assert.Equal(t, "auth chain not found", respJson["error"])

	})

	t.Run("Test start authentication", func(t *testing.T) {
		request := httptest.NewRequest("GET", target, nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)
		assert.Equal(t, 200, recorder.Result().StatusCode)
		cbReq := &models.CallbackRequest{}
		err := json.Unmarshal([]byte(recorder.Body.String()), cbReq)
		assert.NoError(t, err)
		recorder.Result().Header = recorder.Header()
		cookieVal, err := getCookieValue(auth.AuthCookieName, recorder.Result().Cookies())

		assert.NoError(t, err)
		assert.Equal(t, "login", cbReq.Module)
		assert.NotEmpty(t, cookieVal)
	})

	t.Run("Test bad credentials", func(t *testing.T) {

		request := httptest.NewRequest("GET", target, nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)
		assert.Equal(t, 200, recorder.Result().StatusCode)
		cbReq := &models.CallbackRequest{}
		err := json.Unmarshal([]byte(recorder.Body.String()), cbReq)
		assert.NoError(t, err)
		recorder.Result().Header = recorder.Header()
		cookieVal, err := getCookieValue(auth.AuthCookieName, recorder.Result().Cookies())
		assert.NoError(t, err)
		assert.Equal(t, "login", cbReq.Module)

		log.Info("bad login and password")
		for i := range cbReq.Callbacks {
			(&cbReq.Callbacks[i]).Value = "bad"
		}
		body, _ := json.Marshal(cbReq)
		request = httptest.NewRequest("POST", target, bytes.NewBuffer(body))
		authCookie := &http.Cookie{
			Name:  auth.AuthCookieName,
			Value: cookieVal,
		}
		request.AddCookie(authCookie)
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		err = json.Unmarshal([]byte(recorder.Body.String()), cbReq)
		assert.NoError(t, err)
		assert.Equal(t, "Invalid username or password", cbReq.Callbacks[0].Error)
	})

	t.Run("Test bad data", func(t *testing.T) {
		request := httptest.NewRequest("GET", target, nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)
		assert.Equal(t, 200, recorder.Result().StatusCode)
		cbReq := &models.CallbackRequest{}
		err := json.Unmarshal([]byte(recorder.Body.String()), cbReq)
		assert.NoError(t, err)
		recorder.Result().Header = recorder.Header()
		cookieVal, err := getCookieValue(auth.AuthCookieName, recorder.Result().Cookies())
		assert.NoError(t, err)
		assert.Equal(t, "login", cbReq.Module)

		request = httptest.NewRequest("POST", target, bytes.NewBuffer([]byte("bad body")))
		authCookie := &http.Cookie{
			Name:  auth.AuthCookieName,
			Value: cookieVal,
		}
		request.AddCookie(authCookie)
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		var respJson = make(map[string]interface{})
		err = json.Unmarshal([]byte(recorder.Body.String()), &respJson)
		assert.NoError(t, err)
		assert.Equal(t, "bad request", respJson["error"])
		assert.Equal(t, 400, recorder.Result().StatusCode)
	})

	t.Run("Test successful authentication", func(t *testing.T) {
		ur.SetPassword("jerso", "passw0rd")
		request := httptest.NewRequest("GET", target, nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)
		assert.Equal(t, 200, recorder.Result().StatusCode)
		cbReq := &models.CallbackRequest{}
		err := json.Unmarshal([]byte(recorder.Body.String()), cbReq)
		assert.NoError(t, err)
		recorder.Result().Header = recorder.Header()
		cookieVal, err := getCookieValue(auth.AuthCookieName, recorder.Result().Cookies())
		assert.NoError(t, err)
		assert.Equal(t, "login", cbReq.Module)

		recorder.Result().Header = recorder.Header()
		newCookieVal, _ := getCookieValue(auth.AuthCookieName, recorder.Result().Cookies())
		assert.Equal(t, cookieVal, newCookieVal)

		authCookie := &http.Cookie{
			Name:  auth.AuthCookieName,
			Value: cookieVal,
		}

		var login = "jerso"
		var password = "passw0rd"

		(&cbReq.Callbacks[0]).Value = login
		(&cbReq.Callbacks[1]).Value = password

		log.Info("valid login and password")
		body, _ := json.Marshal(cbReq)
		request = httptest.NewRequest("POST", target, bytes.NewBuffer(body))
		request.AddCookie(authCookie)
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, request)

		var respJson = make(map[string]interface{})
		json.Unmarshal([]byte(recorder.Body.String()), &respJson)
		log.Info(recorder.Result())
		assert.NoError(t, err)
		sessionCookie, err := getCookieValue(auth.SessionCookieName, recorder.Result().Cookies())
		assert.NoError(t, err)
		assert.NotEmpty(t, sessionCookie)
		assert.Equal(t, "success", respJson["status"])

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(sessionCookie, claims, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		assert.NoError(t, err)
		assert.NotNil(t, token)

		assert.Equal(t, "dummy", token.Header["jks"])
		assert.Equal(t, login, claims["sub"])

	})
}

func TestIDM(t *testing.T) {

}

//helper functions
func getCookieValue(name string, c []*http.Cookie) (string, error) {

	for _, cookie := range c {
		if cookie.Name == name {
			return cookie.Value, nil
		}
	}
	return "", errors.New("cookie not found")
}
