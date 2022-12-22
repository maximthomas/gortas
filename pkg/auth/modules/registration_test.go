package modules

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/user"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const (
	userName = "johnDoe"
	password = "passw0rdJ0hn"
)

func TestNewRegistrationModule(t *testing.T) {
	rm := getNewRegistrationModule(t)
	assert.Equal(t, "login", rm.PrimaryField.Name)
	assert.Equal(t, 1, len(rm.AdditionalFields))
	assert.Equal(t, true, rm.UsePassword)
	assert.Equal(t, true, rm.UseRepeatPassword)
}

func TestRegistration_Process_InvalidLogin(t *testing.T) {
	tests := []struct {
		email      string
		name       string
		emailError string
		nameError  string
	}{
		{email: "", name: "", emailError: "Email required", nameError: "Name required"},
		{email: "123", name: "John Doe", emailError: "Email invalid", nameError: ""},
	}
	rm := getNewRegistrationModule(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inCbs := []callbacks.Callback{
				{
					Name:  "login",
					Value: tt.email,
				},
				{
					Name:  "name",
					Value: tt.name,
				},
			}
			fs := &state.FlowState{}
			ms, cbs, err := rm.ProcessCallbacks(inCbs, fs)
			assert.NoError(t, err)
			assert.Equal(t, 4, len(cbs))
			assert.Equal(t, tt.emailError, cbs[0].Error)
			assert.Equal(t, tt.nameError, cbs[1].Error)
			assert.Equal(t, state.IN_PROGRESS, ms)
		})
	}

}

func TestRegistration_Process(t *testing.T) {
	rm := getNewRegistrationModule(t)
	t.Run("Test request callbacks", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", "/login", nil)
		lss := &state.FlowState{}
		status, cbs, err := rm.Process(lss)
		log.Print(status, cbs, err)
		assert.Equal(t, 4, len(cbs))
		assert.NoError(t, err)
		assert.Equal(t, state.IN_PROGRESS, status)
		assert.Equal(t, http.StatusOK, recorder.Code)
	})
}

func TestRegistration_ProcessCallbacks(t *testing.T) {
	rm := getNewRegistrationModule(t)
	t.Run("test empty callbacks", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/login", nil)
		lss := &state.FlowState{}
		status, _, err := rm.ProcessCallbacks(nil, lss)
		assert.Error(t, err)
		assert.Equal(t, state.FAIL, status)
	})

	t.Run("test empty fields", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/login", nil)
		lss := &state.FlowState{}
		inCbs := []callbacks.Callback{
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
		status, cbs, err := rm.ProcessCallbacks(inCbs, lss)
		assert.NoError(t, err)
		assert.Equal(t, state.IN_PROGRESS, status)
		assert.Equal(t, "Email required", cbs[0].Error)
		assert.Equal(t, "Name required", cbs[1].Error)
		assert.Equal(t, "Password required", cbs[2].Error)
	})

	t.Run("test user exists", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/login", nil)
		lss := &state.FlowState{}
		inCbs := []callbacks.Callback{
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
			{
				Name:  "repeatPassword",
				Value: password,
			},
		}
		status, cbs, err := rm.ProcessCallbacks(inCbs, lss)
		assert.NoError(t, err)
		assert.Equal(t, state.IN_PROGRESS, status)
		assert.Equal(t, "User exists", cbs[0].Error)
	})

	t.Run("test passwords do not match", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/login", nil)
		lss := &state.FlowState{}
		inCbs := []callbacks.Callback{
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
			{
				Name:  "repeatPassword",
				Value: "bad",
			},
		}
		status, cbs, err := rm.ProcessCallbacks(inCbs, lss)
		assert.NoError(t, err)
		assert.Equal(t, state.IN_PROGRESS, status)
		assert.Equal(t, "Passwords do not match", cbs[3].Error)
	})

	t.Run("test successful registration", func(t *testing.T) {

		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/login", nil)
		lss := &state.FlowState{}
		inCbs := []callbacks.Callback{
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
			{
				Name:  "repeatPassword",
				Value: password,
			},
		}
		status, _, err := rm.ProcessCallbacks(inCbs, lss)
		assert.NoError(t, err)
		assert.Equal(t, state.PASS, status)
		ur := user.GetUserService().Repo
		_, ok := ur.GetUser(userName)
		assert.True(t, ok)
		pValid := ur.ValidatePassword(userName, password)
		assert.True(t, pValid)

	})
}

func getNewRegistrationModule(t *testing.T) *Registration {
	config.SetConfig(config.Config{
		Logger: logrus.New(),
	})
	var b = BaseAuthModule{
		l: config.GetConfig().Logger.WithField("module", "registration"),
		Properties: map[string]interface{}{
			"primaryField": Field{
				Name:       "login",
				Prompt:     "Email",
				Required:   true,
				Validation: "^\\w{4,}$",
			},
			"additionalFields": []Field{{
				Name:     "name",
				Prompt:   "Name",
				Required: true,
			},
			},
		},
	}

	var m = newRegistrationModule(b)
	rm, ok := m.(*Registration)
	assert.True(t, ok)
	return rm
}
