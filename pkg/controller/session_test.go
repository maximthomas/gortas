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
		Session: session.Config{
			Type:    sessRepoType,
			Expires: 60000,
			DataStore: session.DataStore{
				Type:       "in_memory",
				Properties: nil,
			},
			Jwt: session.JWT{
				Issuer:        "http://gortas",
				PrivateKeyPem: privateKeyStr,
			},
		},
	}
	config.SetConfig(&conf)
	statefulSession := session.Session{
		ID: "testSessionId",
		Properties: map[string]string{
			"sub":    "user1",
			"userId": "user1",
			"realm":  "users",
		},
	}
	_, err := session.GetSessionService().CreateSession(statefulSession)
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
	statelessID, _ := token.SignedString(privateKey)
	return statelessID
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
			resp := recorder.Result()
			defer resp.Body.Close()
			assert.Equal(t, tt.wantStatus, resp.StatusCode)
		})
	}
}
