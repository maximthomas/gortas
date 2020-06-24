package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/google/uuid"

	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/models"

	"github.com/gin-gonic/gin"
)

func TestIDMController_Profile(t *testing.T) {
	sessID := uuid.New().String()
	sess := models.Session{
		ID: sessID,
		Properties: map[string]string{
			"test": "test",
		},
	}
	_, err := conf.Session.DataStore.Repo.CreateSession(sess)
	assert.NoError(t, err)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("GET", "/login", nil)
	authCookie := &http.Cookie{
		Name:  auth.SessionCookieName,
		Value: sess.ID,
	}

	c.Request.AddCookie(authCookie)
	c.Set("session", sess)
	idm := NewIDMController(conf)
	idm.Profile(c)
	assert.Equal(t, http.StatusOK, recorder.Code)

	var respJson = make(map[string]interface{})
	err = json.Unmarshal([]byte(recorder.Body.String()), &respJson)
	assert.NoError(t, err)
	assert.Equal(t, sess.ID, respJson["id"])

}
