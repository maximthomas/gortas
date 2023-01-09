package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/session"

	"github.com/stretchr/testify/assert"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func TestMiddleware(t *testing.T) {
	var privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	var privateKeyStr = string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	))
	s := session.SessionConfig{
		Type:    "stateless",
		Expires: 0,
		Jwt: session.SessionJWT{
			Issuer:        "http://gortas",
			PrivateKeyPem: privateKeyStr,
		},
		DataStore: session.SessionDataStore{
			Type:       "",
			Properties: nil,
		},
	}
	err := session.InitSessionService(&s)
	assert.NoError(t, err)

	// Create the Claims
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		Issuer:    "test",
		Subject:   "user1",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	sessJWT, _ := token.SignedString(privateKey)

	m := NewAuthenticatedMiddleware(s)

	var tests = []struct {
		expectedStatus int
		sessionID      string
		name           string
		exists         bool
	}{
		{401, "bad", "Bad token", false},
		{200, sessJWT, "Valid token", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Keys = make(map[string]any)
			c.Request = httptest.NewRequest("GET", "/login", nil)
			authCookie := &http.Cookie{
				Name:  state.SessionCookieName,
				Value: tt.sessionID,
			}
			c.Request.AddCookie(authCookie)
			m(c)
			assert.Equal(t, tt.expectedStatus, recorder.Code)
			_, ok := c.Get("session")
			assert.Equal(t, tt.exists, ok)
		})
	}

}

func TestGetSessionFormRequest(t *testing.T) {
	sessID := uuid.New().String()
	sess := session.Session{
		ID: sessID,

		Properties: map[string]string{
			"test": "test",
			"sub":  "ivan",
		},
	}
	t.Run("Test get session from cookie", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", "/", nil)
		authCookie := &http.Cookie{
			Name:  state.SessionCookieName,
			Value: sess.ID,
		}
		c.Request.AddCookie(authCookie)
		sessionID := getSessionIDFromRequest(c)
		assert.NotEmpty(t, sessionID)
	})

	t.Run("Test get session from auth header", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", "/", nil)

		c.Request.Header.Add("Authorization", "Bearer "+sess.ID)
		sessionID := getSessionIDFromRequest(c)
		assert.NotEmpty(t, sessionID)
	})

	t.Run("Test no session in request", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", "/", nil)

		sessionID := getSessionIDFromRequest(c)
		assert.Empty(t, sessionID)
	})
}
