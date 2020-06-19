package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/models"
)

func TestMiddleware(t *testing.T) {
	assert.Fail(t, "implement test")
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
