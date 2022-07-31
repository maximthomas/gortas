package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/prometheus/common/log"
	"github.com/sirupsen/logrus"

	"github.com/dgrijalva/jwt-go"

	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/repo"
	"github.com/stretchr/testify/assert"
)

var privateKey, _ = rsa.GenerateKey(rand.Reader, 1024)
var publicKey = &privateKey.PublicKey
var ur = repo.NewInMemoryUserRepository()
var (
	authConf = config.Authentication{
		Modules: map[string]config.Module{
			"login":    {Type: "login"},
			"kerberos": {Type: "kerberos"},
			"qr":       {Type: "qr"},
		},
		AuthFlows: map[string]config.AuthFlow{
			"default": {Modules: []config.FlowModule{
				{
					ID: "login",
				},
			}},
			"kerberos": {Modules: []config.FlowModule{
				{
					ID: "kerberos",
				},
			}},
			"qr": {Modules: []config.FlowModule{
				{
					ID: "qr",
				},
			}},
		},
	}

	logger = logrus.New()
	conf   = config.Config{
		Authentication: authConf,
		UserDataStore: config.UserDataStore{
			Repo: ur,
		},
		Logger: logger,
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
	router *gin.Engine
)

func init() {
	config.SetConfig(conf)
	router = SetupRouter(conf)
}

func TestSetupRouter(t *testing.T) {
	assert.Equal(t, 3, len(router.Routes()))
}

const target = "http://localhost/gortas/v1/auth/default"

func TestLogin(t *testing.T) {
	t.Run("Test not existing realm", func(t *testing.T) {
		request := httptest.NewRequest("GET", "http://localhost/gortas/v1/auth/bad", nil)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		assert.Equal(t, 401, recorder.Result().StatusCode)
		var respJson = make(map[string]interface{})
		err := json.Unmarshal(recorder.Body.Bytes(), &respJson)
		assert.NoError(t, err)
		msg := respJson["message"].(string)
		assert.Equal(t, "auth flow bad not found", msg)

	})

	t.Run("Test start authentication", func(t *testing.T) {
		request := httptest.NewRequest("GET", target, nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)
		assert.Equal(t, 200, recorder.Result().StatusCode)
		cbReq := &callbacks.Request{}
		err := json.Unmarshal(recorder.Body.Bytes(), cbReq)
		assert.NoError(t, err)
		recorder.Result().Header = recorder.Header()
		cookieVal, err := getCookieValue(state.FlowCookieName, recorder.Result().Cookies())

		assert.NoError(t, err)
		assert.Equal(t, "login", cbReq.Module)
		assert.NotEmpty(t, cookieVal)
	})

	t.Run("Test bad credentials", func(t *testing.T) {

		request := httptest.NewRequest("GET", target, nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)
		assert.Equal(t, 200, recorder.Result().StatusCode)
		cbReq := &callbacks.Request{}
		err := json.Unmarshal(recorder.Body.Bytes(), cbReq)
		assert.NoError(t, err)
		recorder.Result().Header = recorder.Header()
		cookieVal, err := getCookieValue(state.FlowCookieName, recorder.Result().Cookies())
		assert.NoError(t, err)
		assert.Equal(t, "login", cbReq.Module)

		log.Info("bad login and password")
		for i := range cbReq.Callbacks {
			(&cbReq.Callbacks[i]).Value = "bad"
		}
		body, _ := json.Marshal(cbReq)
		request = httptest.NewRequest("POST", target, bytes.NewBuffer(body))
		authCookie := &http.Cookie{
			Name:  state.FlowCookieName,
			Value: cookieVal,
		}
		request.AddCookie(authCookie)
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		err = json.Unmarshal(recorder.Body.Bytes(), cbReq)
		assert.NoError(t, err)
		assert.Equal(t, "Invalid username or password", cbReq.Callbacks[0].Error)
	})

	t.Run("Test bad data", func(t *testing.T) {
		request := httptest.NewRequest("GET", target, nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)
		assert.Equal(t, 200, recorder.Result().StatusCode)
		cbReq := &callbacks.Request{}
		err := json.Unmarshal(recorder.Body.Bytes(), cbReq)
		assert.NoError(t, err)
		recorder.Result().Header = recorder.Header()
		cookieVal, err := getCookieValue(state.FlowCookieName, recorder.Result().Cookies())
		assert.NoError(t, err)
		assert.Equal(t, "login", cbReq.Module)

		request = httptest.NewRequest("POST", target, bytes.NewBuffer([]byte("bad body")))
		authCookie := &http.Cookie{
			Name:  state.FlowCookieName,
			Value: cookieVal,
		}
		request.AddCookie(authCookie)
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		var respJson = make(map[string]interface{})
		err = json.Unmarshal(recorder.Body.Bytes(), &respJson)
		assert.NoError(t, err)
		assert.Equal(t, "bad request", respJson["error"])
		assert.Equal(t, 400, recorder.Result().StatusCode)
	})

	t.Run("Test successful authentication", func(t *testing.T) {
		_ = ur.SetPassword("jerso", "passw0rd")
		request := httptest.NewRequest("GET", target, nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)
		assert.Equal(t, 200, recorder.Result().StatusCode)
		cbReq := &callbacks.Request{}
		err := json.Unmarshal(recorder.Body.Bytes(), cbReq)
		assert.NoError(t, err)
		recorder.Result().Header = recorder.Header()
		cookieVal, err := getCookieValue(state.FlowCookieName, recorder.Result().Cookies())
		assert.NoError(t, err)
		assert.Equal(t, "login", cbReq.Module)

		recorder.Result().Header = recorder.Header()
		newCookieVal, _ := getCookieValue(state.FlowCookieName, recorder.Result().Cookies())
		assert.Equal(t, cookieVal, newCookieVal)

		authCookie := &http.Cookie{
			Name:  state.FlowCookieName,
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
		_ = json.Unmarshal(recorder.Body.Bytes(), &respJson)
		log.Info(recorder.Result())
		assert.NoError(t, err)
		sessionCookie, err := getCookieValue(state.SessionCookieName, recorder.Result().Cookies())
		assert.NoError(t, err)
		assert.NotEmpty(t, sessionCookie)
		assert.NotEmpty(t, respJson["token"])

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
	t.Skip()
	//TODO v2 implement test
	assert.Fail(t, "implement test")
}

func TestRegisterQR(t *testing.T) {
	t.Skip()
	assert.Fail(t, "implement test")
	sessionId := doLogin("user1", "password")
	assert.NotEmpty(t, sessionId)

	//getting QR code
	request := httptest.NewRequest("GET", "http://localhost/gortas/v1/idm/otp/qr", nil)

	sessionCookie := &http.Cookie{
		Name:  state.SessionCookieName,
		Value: sessionId,
	}
	request.AddCookie(sessionCookie)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	var resp map[string]string
	err := json.Unmarshal([]byte(recorder.Body.String()), &resp)
	assert.NoError(t, err)
	qrB64, ok := resp["qr"]
	assert.True(t, ok)
	assert.NotEmpty(t, qrB64)
	assert.True(t, strings.HasPrefix(qrB64, "data"))

	//QR register
	request = httptest.NewRequest("POST", "http://localhost/gortas/v1/idm/otp/qr", nil)
	request.AddCookie(sessionCookie)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	err = json.Unmarshal(recorder.Body.Bytes(), &resp)
	assert.NoError(t, err)
	secret, ok := resp["secret"]
	assert.True(t, ok)
	assert.NotEmpty(t, secret)
}

func TestAuthQR(t *testing.T) {
	t.Skip()
	assert.Fail(t, "implement test")
	const secret = "s3cr3t"
	user1, _ := ur.GetUser("user1")
	user1.SetProperty("passwordless.qr", fmt.Sprintf(`{"secret": "%s"}`, secret))
	_ = ur.UpdateUser(user1)

	request := httptest.NewRequest("GET", "http://localhost/gortas/v1/login/staff/qr", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)

	cookieVal, _ := getCookieValue(state.FlowCookieName, recorder.Result().Cookies())

	authCookie := &http.Cookie{
		Name:  state.FlowCookieName,
		Value: cookieVal,
	}

	cbReq := &callbacks.Request{}
	err := json.Unmarshal([]byte(recorder.Body.String()), cbReq)
	assert.NoError(t, err)

	//auth QR
	authQRBody := fmt.Sprintf(`{"sid":"%s", "uid": "%s", "realm":"%s", "secret": "%s"}`, cookieVal, "user1", "staff", secret)
	request = httptest.NewRequest("POST", "http://localhost/gortas/v1/service/otp/qr/login", bytes.NewBuffer([]byte(authQRBody)))
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)

	//try to authenticate
	request = httptest.NewRequest("POST", "http://localhost/gortas/v1/login/staff/qr", bytes.NewBuffer([]byte(`{}`)))
	request.AddCookie(authCookie)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)

	var respJSON = make(map[string]interface{})
	_ = json.Unmarshal([]byte(recorder.Body.String()), &respJSON)
	log.Info(recorder.Result())
	assert.NoError(t, err)
	sessionCookie, err := getCookieValue(state.SessionCookieName, recorder.Result().Cookies())
	assert.NoError(t, err)
	assert.NotEmpty(t, sessionCookie)
	assert.Equal(t, "success", respJSON["status"])

}

func doLogin(login string, password string) (sessionId string) {
	request := httptest.NewRequest("GET", target, nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)
	cbReq := &callbacks.Request{}
	_ = json.Unmarshal([]byte(recorder.Body.String()), cbReq)
	recorder.Result().Header = recorder.Header()
	cookieVal, _ := getCookieValue(state.FlowCookieName, recorder.Result().Cookies())

	authCookie := &http.Cookie{
		Name:  state.FlowCookieName,
		Value: cookieVal,
	}

	(&cbReq.Callbacks[0]).Value = login
	(&cbReq.Callbacks[1]).Value = password

	body, _ := json.Marshal(cbReq)
	request = httptest.NewRequest("POST", target, bytes.NewBuffer(body))
	request.AddCookie(authCookie)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	sessionId, _ = getCookieValue(state.SessionCookieName, recorder.Result().Cookies())
	return sessionId
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
