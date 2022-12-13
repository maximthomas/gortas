package controller

import (
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/session"
	"github.com/stretchr/testify/assert"
)

func setupConfig(sessRepoType string) {

	conf := config.Config{
		Logger: logger,
		Session: config.Session{
			Type:    sessRepoType,
			Expires: 60000,
			DataStore: config.SessionDataStore{
				Repo:       session.NewInMemorySessionRepository(logger),
				Type:       "in_memory",
				Properties: nil,
			},
			Jwt: config.SessionJWT{
				Issuer:        "http://gortas",
				PrivateKeyPem: "",
				PrivateKeyID:  "http://gortas",
				PrivateKey:    privateKey,
				PublicKey:     publicKey,
			},
		},
	}
	config.SetConfig(conf)
	statefulSession := session.Session{
		ID: "testSessionId",
		Properties: map[string]string{
			"sub":    "user1",
			"userId": "user1",
			"realm":  "users",
		},
	}
	_, err := conf.Session.DataStore.Repo.CreateSession(statefulSession)
	if err != nil {
		panic(err)
	}
}

func getTestJWT() string {
	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	exp := time.Second * time.Duration(rand.Intn(1000))
	claims["id"] = "testSessionId"
	claims["exp"] = time.Now().Add(exp).Unix()
	claims["jti"] = "test"
	claims["iat"] = time.Now().Unix()
	claims["iss"] = "http://gortas"
	claims["sub"] = "user1"
	claims["realm"] = "realm1"
	statelessId, _ := token.SignedString(privateKey)
	return statelessId
}

func TestSessionController_SessionInfo(t *testing.T) {
	testJWT := getTestJWT()
	setupConfig("stateless")
	sc := NewSessionController()
	assert.NotNil(t, sc)

	tests := []struct {
		name       string
		getRequest func() *http.Request
		wantStatus int
	}{
		{
			name: "get_existing_session_header",
			getRequest: func() *http.Request {
				request := httptest.NewRequest("GET", "/", nil)
				request.Header.Set("Authorization", "Bearer "+testJWT)
				return request
			},
			wantStatus: 200,
		},
		{
			name: "get_existing_session_cookie",
			getRequest: func() *http.Request {
				request := httptest.NewRequest("GET", "/", nil)
				authCookie := &http.Cookie{
					Name:  state.SessionCookieName,
					Value: testJWT,
				}
				request.AddCookie(authCookie)
				return request
			},
			wantStatus: 200,
		},
		{
			name: "get_empty_session",
			getRequest: func() *http.Request {
				request := httptest.NewRequest("GET", "/", nil)
				return request
			},
			wantStatus: 404,
		},
		{
			name: "get_bad_session",
			getRequest: func() *http.Request {
				request := httptest.NewRequest("GET", "/", nil)
				return request
			},
			wantStatus: 404,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = tt.getRequest()
			sc.SessionInfo(c)
			assert.Equal(t, tt.wantStatus, recorder.Result().StatusCode)
		})
	}
}

func Test_getSessionData(t *testing.T) {

	statelessId := getTestJWT()

	type args struct {
		sessionId string
	}
	tests := []struct {
		name          string
		args          args
		wantSessionId string
		wantErr       bool
		setupFunc     func()
	}{
		{
			name: "stateful_session_found",
			args: args{
				sessionId: "testSessionId",
			},
			wantSessionId: "testSessionId",
			wantErr:       false,
			setupFunc:     func() { setupConfig("stateful") },
		},
		{
			name: "stateful_session_nof_found",
			args: args{
				sessionId: "badSessionId",
			},
			wantErr:   true,
			setupFunc: func() { setupConfig("stateful") },
		},
		{
			name: "stateless_valid_session",
			args: args{
				sessionId: statelessId,
			},
			wantErr:       false,
			wantSessionId: "testSessionId",
			setupFunc:     func() { setupConfig("stateless") },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupFunc()
			sc := NewSessionController()
			gotSession, err := sc.getSessionData(tt.args.sessionId)
			if (err != nil) != tt.wantErr {
				t.Errorf("getSessionData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				assert.Equal(t, tt.wantSessionId, gotSession["id"])
			}
		})
	}
}
