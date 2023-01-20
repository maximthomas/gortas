package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/log"
	"github.com/maximthomas/gortas/pkg/user"
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
			assert.Equal(t, state.InProgress, ms)
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
		fmt.Print(status, cbs, err)
		assert.Equal(t, 4, len(cbs))
		assert.NoError(t, err)
		assert.Equal(t, state.InProgress, status)
		assert.Equal(t, http.StatusOK, recorder.Code)
	})
}

func TestRegistration_ProcessCallbacks(t *testing.T) {
	rm := getNewRegistrationModule(t)

	tests := []struct {
		name       string
		inCbs      []callbacks.Callback
		assertions func(t *testing.T, status state.ModuleStatus, cbs []callbacks.Callback, err error)
	}{
		{
			name:  "test empty callbacks",
			inCbs: nil,
			assertions: func(t *testing.T, status state.ModuleStatus, cbs []callbacks.Callback, err error) {
				assert.Error(t, err)
				assert.Equal(t, state.Fail, status)
			},
		},
		{
			name: "test empty fields",
			inCbs: []callbacks.Callback{
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
			},
			assertions: func(t *testing.T, status state.ModuleStatus, cbs []callbacks.Callback, err error) {
				assert.NoError(t, err)
				assert.Equal(t, state.InProgress, status)
				assert.Equal(t, "Email required", cbs[0].Error)
				assert.Equal(t, "Name required", cbs[1].Error)
				assert.Equal(t, "Password required", cbs[2].Error)
			},
		},
		{
			name: "test user exists",
			inCbs: []callbacks.Callback{
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
			},
			assertions: func(t *testing.T, status state.ModuleStatus, cbs []callbacks.Callback, err error) {
				assert.Equal(t, state.InProgress, status)
				assert.Equal(t, "User exists", cbs[0].Error)
			},
		},
		{
			name: "test passwords do not match",
			inCbs: []callbacks.Callback{
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
			},
			assertions: func(t *testing.T, status state.ModuleStatus, cbs []callbacks.Callback, err error) {
				assert.NoError(t, err)
				assert.Equal(t, state.InProgress, status)
				assert.Equal(t, "Passwords do not match", cbs[3].Error)
			},
		},
		{
			name: "test successful registration",
			inCbs: []callbacks.Callback{
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
			},
			assertions: func(t *testing.T, status state.ModuleStatus, cbs []callbacks.Callback, err error) {
				assert.NoError(t, err)
				assert.Equal(t, state.Pass, status)
				us := user.GetUserService()
				_, ok := us.GetUser(userName)
				assert.True(t, ok)
				pValid := us.ValidatePassword(userName, password)
				assert.True(t, pValid)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest("POST", "/login", nil)
			lss := &state.FlowState{}
			status, cbs, err := rm.ProcessCallbacks(tt.inCbs, lss)
			tt.assertions(t, status, cbs, err)
		})
	}
}

func getNewRegistrationModule(t *testing.T) *Registration {
	config.SetConfig(&config.Config{})
	var b = BaseAuthModule{
		l: log.WithField("module", "registration"),
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
