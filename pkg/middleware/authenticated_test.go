package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/repo"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/models"
)

func TestMiddleware(t *testing.T) {
	var privateKey, _ = rsa.GenerateKey(rand.Reader, 1024)
	var publicKey = &privateKey.PublicKey
	s := config.Session{
		Type:    "stateless",
		Expires: 0,
		Jwt: config.SessionJWT{
			Issuer:        "http://gortas",
			PrivateKeyPem: "",
			PrivateKeyID:  "",
			PrivateKey:    privateKey,
			PublicKey:     publicKey,
		},
		DataStore: config.SessionDataStore{
			Repo:       repo.NewInMemorySessionRepository(nil),
			Type:       "",
			Properties: nil,
		},
	}

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
		sessionId      string
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
			c.Keys = make(map[string]interface{})
			c.Request = httptest.NewRequest("GET", "/login", nil)
			authCookie := &http.Cookie{
				Name:  auth.SessionCookieName,
				Value: tt.sessionId,
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
	sess := models.Session{
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
			Name:  auth.SessionCookieName,
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
