package modules

import (
	"testing"

	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/user"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestCredentialsProcess(t *testing.T) {
	cm := getCredentialsModule(t)
	ms, cbs, err := cm.Process(nil)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(cbs))
	assert.Equal(t, state.IN_PROGRESS, ms)

	assert.Equal(t, "login", cbs[0].Name)
	assert.Equal(t, "name", cbs[1].Name)
}

func TestCredentialsProcessCallbacks(t *testing.T) {

	cm := getCredentialsModule(t)
	const testEmail = "test@test.com"
	const testName = "John Doe"

	var tests = []struct {
		test     string
		email    string
		name     string
		emailErr string
		nameErr  string
		status   state.ModuleStatus
	}{
		{
			test:     "empty name email",
			email:    "",
			name:     "",
			emailErr: "Email required",
			nameErr:  "Name required",
			status:   state.IN_PROGRESS,
		},
		{
			test:     "invalid email",
			email:    "bad",
			name:     testName,
			emailErr: "Email invalid",
			nameErr:  "",
			status:   state.IN_PROGRESS,
		},
		{
			test:     "valid name email",
			email:    testEmail,
			name:     testName,
			emailErr: "",
			nameErr:  "",
			status:   state.PASS,
		},
	}
	for _, tt := range tests {
		t.Run(tt.test, func(t *testing.T) {
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
			var fs state.FlowState
			ms, cbs, err := cm.ProcessCallbacks(inCbs, &fs)
			assert.NoError(t, err)
			assert.Equal(t, tt.status, ms)
			switch ms {
			case state.IN_PROGRESS:
				assert.Equal(t, 2, len(cbs))
				assert.Equal(t, tt.emailErr, cbs[0].Error)
				assert.Equal(t, tt.nameErr, cbs[1].Error)
			case state.PASS:
				assert.Equal(t, testEmail, cm.credentialsState.UserID)
				assert.Equal(t, testName, cm.credentialsState.Properties["name"])

				assert.Equal(t, testEmail, cm.State["userId"].(string))
				props := cm.State["properties"].(map[string]string)
				name := props["name"]
				assert.Equal(t, testName, name)
			}
		})
	}
}

func TestCredentiaslPostProcess(t *testing.T) {
	const testEmail = "test@test.com"
	const testName = "John Doe"

	cm := getCredentialsModule(t)
	cm.credentialsState = &credentialsState{
		UserID: testEmail,
		Properties: map[string]string{
			"name": testName,
		},
	}

	us := user.GetUserService()
	_, ok := us.GetUser(testEmail)
	assert.False(t, ok, "User does not exists")
	fs := &state.FlowState{}
	err := cm.PostProcess(fs)
	assert.NoError(t, err)

	u, ok := us.GetUser(testEmail)
	assert.True(t, ok, "user exists")
	assert.Equal(t, testEmail, u.ID)
	assert.Equal(t, testName, u.Properties["name"])
}

func TestGetCredentialsModule(t *testing.T) {
	cm := getCredentialsModule(t)
	assert.NotNil(t, cm)

}

func getCredentialsModule(t *testing.T) *Credentials {
	conf := config.Config{}
	config.SetConfig(&conf)

	const emailRegexp = "^([a-z0-9_-]+)(@[a-z0-9-]+)(\\.[a-z]+|\\.[a-z]+\\.[a-z]+)?$"
	var b = BaseAuthModule{
		l: logrus.New().WithField("module", "credentials"),
		Properties: map[string]interface{}{
			"primaryField": Field{
				Name:       "login",
				Prompt:     "Email",
				Required:   true,
				Validation: emailRegexp,
			},
			"additionalFields": []Field{{
				Name:     "name",
				Prompt:   "Name",
				Required: true,
			},
			},
		},
		State: make(map[string]interface{}),
	}
	var m = newCredentials(b)
	cm, ok := m.(*Credentials)
	assert.True(t, ok)
	return cm
}
