package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/dgrijalva/jwt-go"

	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/session"
	"github.com/maximthomas/gortas/pkg/user"
	"github.com/stretchr/testify/assert"
)

var privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
var privateKeyStr = string(pem.EncodeToMemory(
	&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	},
))

var publicKey = &privateKey.PublicKey

var us user.Service
var ss session.Service
var (
	flows = map[string]config.Flow{
		"default": {Modules: []config.Module{
			{
				ID:   "login",
				Type: "login",
			},
		}},
		"kerberos": {Modules: []config.Module{
			{
				ID:   "kerberos",
				Type: "kerberos",
			},
		}},
		"qr": {Modules: []config.Module{
			{
				ID:   "qr",
				Type: "qr",
			},
		}},
	}

	conf = config.Config{
		Flows: flows,
		Session: session.Config{
			Type:    "stateless",
			Expires: 60000,
			Jwt: session.JWT{
				Issuer:        "http://gortas",
				PrivateKeyPem: privateKeyStr,
			},
		},
	}
	router *gin.Engine
)

func init() {
	config.SetConfig(&conf)
	router = SetupRouter(&conf)
	us = user.GetUserService()
	ss = *session.GetSessionService()
}

func TestSetupRouter(t *testing.T) {
	assert.Equal(t, 4, len(router.Routes()))
}

const target = "http://localhost/gortas/v1/auth/default"

func TestLogin(t *testing.T) {

	t.Run("Test start authentication", func(t *testing.T) {
		request := httptest.NewRequest("GET", target, nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)
		resp := recorder.Result()
		defer resp.Body.Close()
		assert.Equal(t, 200, resp.StatusCode)
		cbReq := &callbacks.Request{}
		err := json.Unmarshal(recorder.Body.Bytes(), cbReq)
		assert.NoError(t, err)
		resp.Header = recorder.Header()
		cookieVal, err := getCookieValue(state.FlowCookieName, resp.Cookies())

		assert.NoError(t, err)
		assert.Equal(t, "login", cbReq.Module)
		assert.NotEmpty(t, cookieVal)
	})

	t.Run("Test bad credentials", func(t *testing.T) {
		request := httptest.NewRequest("GET", target, nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		resp := recorder.Result()
		defer resp.Body.Close()

		assert.Equal(t, 200, resp.StatusCode)
		cbReq := &callbacks.Request{}
		err := json.Unmarshal(recorder.Body.Bytes(), cbReq)
		assert.NoError(t, err)
		resp.Header = recorder.Header()
		cookieVal, err := getCookieValue(state.FlowCookieName, resp.Cookies())
		assert.NoError(t, err)
		assert.Equal(t, "login", cbReq.Module)

		log.Print("bad login and password")
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

		resp := recorder.Result()
		defer resp.Body.Close()

		assert.Equal(t, 200, resp.StatusCode)
		cbReq := &callbacks.Request{}
		err := json.Unmarshal(recorder.Body.Bytes(), cbReq)
		assert.NoError(t, err)
		resp.Header = recorder.Header()
		cookieVal, err := getCookieValue(state.FlowCookieName, resp.Cookies())
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
		resp = recorder.Result()
		defer resp.Body.Close()
		var respJSON = make(map[string]interface{})
		err = json.Unmarshal(recorder.Body.Bytes(), &respJSON)
		assert.NoError(t, err)
		assert.Equal(t, "bad request", respJSON["error"])
		assert.Equal(t, 400, resp.StatusCode)
	})

	t.Run("Test successful authentication", func(t *testing.T) {
		_ = us.SetPassword("jerso", "passw0rd")
		request := httptest.NewRequest("GET", target, nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		resp := recorder.Result()

		assert.Equal(t, 200, resp.StatusCode)
		cbReq := &callbacks.Request{}
		err := json.Unmarshal(recorder.Body.Bytes(), cbReq)
		assert.NoError(t, err)
		resp.Header = recorder.Header()
		cookieVal, err := getCookieValue(state.FlowCookieName, resp.Cookies())
		assert.NoError(t, err)
		assert.Equal(t, "login", cbReq.Module)

		resp.Header = recorder.Header()
		newCookieVal, _ := getCookieValue(state.FlowCookieName, resp.Cookies())
		assert.Equal(t, cookieVal, newCookieVal)
		resp.Body.Close()

		authCookie := &http.Cookie{
			Name:  state.FlowCookieName,
			Value: cookieVal,
		}

		var login = "jerso"
		var password = "passw0rd"

		(&cbReq.Callbacks[0]).Value = login
		(&cbReq.Callbacks[1]).Value = password

		log.Print("valid login and password")
		body, _ := json.Marshal(cbReq)
		request = httptest.NewRequest("POST", target, bytes.NewBuffer(body))
		request.AddCookie(authCookie)
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, request)

		resp = recorder.Result()

		var respJSON = make(map[string]interface{})
		_ = json.Unmarshal(recorder.Body.Bytes(), &respJSON)
		log.Print(resp)
		assert.NoError(t, err)
		sessionCookie, err := getCookieValue(state.SessionCookieName, resp.Cookies())
		assert.NoError(t, err)
		assert.NotEmpty(t, sessionCookie)
		assert.NotEmpty(t, respJSON["token"])
		resp.Body.Close()
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(sessionCookie, claims, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		assert.NoError(t, err)
		assert.NotNil(t, token)

		assert.NotEmpty(t, token.Header["jks"])
		assert.Equal(t, login, claims["sub"])

	})

	t.Run("test authentication without init", func(t *testing.T) {
		const login = "jerso"
		const password = "passw0rd"

		_ = us.SetPassword(login, password)

		cbReq := callbacks.Request{
			Callbacks: []callbacks.Callback{
				{
					Name:  "login",
					Value: login,
				},
				{
					Name:  "password",
					Value: password,
				},
			},
		}

		log.Print("valid login and password")
		body, _ := json.Marshal(cbReq)
		request := httptest.NewRequest("POST", target, bytes.NewBuffer(body))
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		resp := recorder.Result()
		defer resp.Body.Close()
		var respJSON = make(map[string]interface{})
		_ = json.Unmarshal(recorder.Body.Bytes(), &respJSON)
		log.Print(resp)
		sessionCookie, err := getCookieValue(state.SessionCookieName, resp.Cookies())
		assert.NoError(t, err)
		assert.NotEmpty(t, sessionCookie)
		assert.NotEmpty(t, respJSON["token"])
	})

	t.Run("test authentication without init invalid data", func(t *testing.T) {
		cbReq := callbacks.Request{
			Callbacks: []callbacks.Callback{
				{
					Name:  "login",
					Value: "bad",
				},
			},
		}

		log.Print("invalid auth data")
		body, _ := json.Marshal(cbReq)
		request := httptest.NewRequest("POST", target, bytes.NewBuffer(body))
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)

		var respJSON = make(map[string]interface{})
		_ = json.Unmarshal(recorder.Body.Bytes(), &respJSON)
		assert.Equal(t, "fail", respJSON["status"])
		assert.Equal(t, 401, recorder.Result().StatusCode)
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
	sessionID := doLogin("user1", "password")
	assert.NotEmpty(t, sessionID)

	//getting QR code
	request := httptest.NewRequest("GET", "http://localhost/gortas/v1/idm/otp/qr", nil)

	sessionCookie := &http.Cookie{
		Name:  state.SessionCookieName,
		Value: sessionID,
	}
	request.AddCookie(sessionCookie)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	var resp map[string]string
	err := json.Unmarshal(recorder.Body.Bytes(), &resp)
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
	user1, _ := us.GetUser("user1")
	user1.SetProperty("passwordless.qr", fmt.Sprintf(`{"secret": "%q"}`, secret))
	_ = us.UpdateUser(user1)

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
	err := json.Unmarshal(recorder.Body.Bytes(), cbReq)
	assert.NoError(t, err)

	//auth QR
	authQRBody := fmt.Sprintf(`{"sid":"%q", "uid": "%q", "realm":"%q", "secret": "%q"}`, cookieVal, "user1", "staff", secret)
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
	_ = json.Unmarshal(recorder.Body.Bytes(), &respJSON)
	log.Print(recorder.Result())
	assert.NoError(t, err)
	sessionCookie, err := getCookieValue(state.SessionCookieName, recorder.Result().Cookies())
	assert.NoError(t, err)
	assert.NotEmpty(t, sessionCookie)
	assert.Equal(t, "success", respJSON["status"])
}

func doLogin(login, password string) (sessionID string) {
	request := httptest.NewRequest("GET", target, nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)
	cbReq := &callbacks.Request{}
	_ = json.Unmarshal(recorder.Body.Bytes(), cbReq)
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
	sessionID, _ = getCookieValue(state.SessionCookieName, recorder.Result().Cookies())
	return sessionID
}

// helper functions
func getCookieValue(name string, c []*http.Cookie) (string, error) {

	for _, cookie := range c {
		if cookie.Name == name {
			return cookie.Value, nil
		}
	}
	return "", errors.New("cookie not found")
}
