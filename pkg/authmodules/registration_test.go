package authmodules

import (
	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/models"
	"github.com/maximthomas/gortas/pkg/repo"
	"github.com/stretchr/testify/assert"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	userName = "johnDoe"
	password = "passw0rdJ0hn"
)

var b = BaseAuthModule{
	properties: map[string]interface{}{
		keyAdditionalFields: []AdditionalFiled{{
			DataStore: "name",
			Prompt:    "Name",
			Required:  true,
		},
		},
	},
	r: config.Realm{
		ID:         "",
		Modules:    nil,
		AuthChains: nil,
		UserDataStore: config.UserDataStore{
			Repo: repo.NewInMemoryUserRepository(),
		},
	},
}

func TestRegistration_Process(t *testing.T) {
	var rm = NewRegistrationModule(b)

	t.Run("Test request callbacks", func(t *testing.T) {

		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", "/login", nil)
		lss := &auth.LoginSessionState{}
		status, cbs, err := rm.Process(lss, c)
		log.Print(status, cbs, err)
		assert.Equal(t, 3, len(cbs))
		assert.NoError(t, err)
		assert.Equal(t, auth.InProgress, status)
		assert.Equal(t, http.StatusOK, recorder.Code)
	})
}

func TestRegistration_ProcessCallbacks(t *testing.T) {
	var rm = NewRegistrationModule(b)
	t.Run("test empty callbacks", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/login", nil)
		lss := &auth.LoginSessionState{}
		status, _, err := rm.ProcessCallbacks(nil, lss, c)
		assert.Error(t, err)
		assert.Equal(t, auth.Fail, status)
	})

	t.Run("test empty fields", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/login", nil)
		lss := &auth.LoginSessionState{}
		inCbs := []models.Callback{
			{
				Name:  "login",
				Value: "",
			},
			{
				Name:  "name",
				Value: "",
			},
			{
				Name:  "password",
				Value: "",
			},
		}
		status, cbs, err := rm.ProcessCallbacks(inCbs, lss, c)
		assert.NoError(t, err)
		assert.Equal(t, auth.InProgress, status)
		assert.Equal(t, "Login required", cbs[0].Error)
		assert.Equal(t, "Name required", cbs[1].Error)
		assert.Equal(t, "Password required", cbs[2].Error)
	})

	t.Run("test user exists", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/login", nil)
		lss := &auth.LoginSessionState{}
		inCbs := []models.Callback{
			{
				Name:  "login",
				Value: "user1",
			},
			{
				Name:  "name",
				Value: "John Doe",
			},
			{
				Name:  "password",
				Value: password,
			},
		}
		status, cbs, err := rm.ProcessCallbacks(inCbs, lss, c)
		assert.NoError(t, err)
		assert.Equal(t, auth.InProgress, status)
		assert.Equal(t, "User exists", cbs[0].Error)
	})

	t.Run("test successful registration", func(t *testing.T) {

		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/login", nil)
		lss := &auth.LoginSessionState{}
		inCbs := []models.Callback{
			{
				Name:  "login",
				Value: userName,
			},
			{
				Name:  "name",
				Value: "John Doe",
			},
			{
				Name:  "password",
				Value: password,
			},
		}
		status, _, err := rm.ProcessCallbacks(inCbs, lss, c)
		assert.NoError(t, err)
		assert.Equal(t, auth.Pass, status)
		_, ok := rm.r.UserDataStore.Repo.GetUser(userName)
		assert.True(t, ok)
		pValid := rm.r.UserDataStore.Repo.ValidatePassword(userName, password)
		assert.True(t, pValid)

	})
}
