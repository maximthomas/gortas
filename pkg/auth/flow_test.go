package auth

import (
	"testing"

	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/constants"

	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/models"
	"github.com/maximthomas/gortas/pkg/repo"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const testFlowId = "test-flow-id"
const corruptedFlowId = "corrupted-flow-id"

func init() {
	logger := logrus.New()
	sr := repo.NewInMemorySessionRepository(logger)
	s := models.Session{
		ID: testFlowId,
		Properties: map[string]string{
			constants.FlowStateSessionProperty: "{}",
		},
	}
	_, _ = sr.CreateSession(s)
	corruptedSession := models.Session{
		ID: corruptedFlowId,
		Properties: map[string]string{
			constants.FlowStateSessionProperty: "bad",
		},
	}
	_, _ = sr.CreateSession(corruptedSession)
	ac := config.Authentication{
		Modules: map[string]config.Module{
			"login": {Type: "login"},
			"registration": {
				Type: "registration",
				Properties: map[string]interface{}{
					"additionalFields": []map[interface{}]interface{}{{
						"dataStore": "name",
						"prompt":    "Name",
					}},
				},
			},
		},

		AuthFlows: map[string]config.AuthFlow{
			"login": {Modules: []config.FlowModule{
				{
					ID: "login",
				},
			}},
			"register": {Modules: []config.FlowModule{
				{
					ID: "registration",
					Properties: map[string]interface{}{
						"testProp": "testVal",
					},
				},
			}},
			"sso": {Modules: []config.FlowModule{}},
		},
	}

	conf := config.Config{
		Authentication: ac,
		UserDataStore: config.UserDataStore{
			Repo: repo.NewInMemoryUserRepository(),
		},
		Logger: logger,
		Session: config.Session{
			Type:      "stateful",
			DataStore: config.SessionDataStore{Repo: sr},
		},
	}
	config.SetConfig(conf)
}

func TestGetFlow(t *testing.T) {

	tests := []struct {
		name       string
		realm      string
		flowName   string
		flowId     string
		checkError func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool
		checkFlow  func(t assert.TestingT, f *Flow)
	}{
		{name: "existing flow", flowName: "login", checkError: assert.NoError, checkFlow: func(t assert.TestingT, f *Flow) { assert.NotNil(t, f) }},
		{name: "non existing flow", flowName: "bad", checkError: assert.Error, checkFlow: func(t assert.TestingT, f *Flow) { assert.Nil(t, f) }},
		{name: "existing flowId", flowId: testFlowId, checkError: assert.NoError, checkFlow: func(t assert.TestingT, f *Flow) { assert.NotNil(t, f) }},
		{name: "corrupted flowId", flowId: corruptedFlowId, checkError: assert.Error, checkFlow: func(t assert.TestingT, f *Flow) { assert.Nil(t, f) }},
		{name: "non existing flowId", flowName: "login", flowId: "bad-flow-id", checkError: assert.NoError, checkFlow: func(t assert.TestingT, f *Flow) { assert.NotNil(t, f) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := GetFlow(tt.flowName, tt.flowId)
			tt.checkError(t, err)
			tt.checkFlow(t, f)
		})
	}
}

func TestProcess(t *testing.T) {
	f, _ := GetFlow("login", "")
	var cbReq callbacks.Request
	cbResp, err := f.Process(cbReq, nil, nil)
	assert.NoError(t, err)
	assert.True(t, len(cbResp.Callbacks) > 0)
	assert.Equal(t, "login", cbResp.Module)
	assert.NotEmpty(t, cbResp.FlowId)

	//invalid login and password
	cbReq = callbacks.Request{
		Module:    cbResp.Module,
		Callbacks: cbResp.Callbacks,
	}
	cbReq.Callbacks[0].Value = "test"
	cbReq.Callbacks[1].Value = "test"
	cbResp, err = f.Process(cbReq, nil, nil)
	assert.NoError(t, err)
	assert.True(t, len(cbResp.Callbacks) > 0)
	assert.Equal(t, "login", cbResp.Module)
	assert.NotEmpty(t, cbResp.FlowId)
	assert.Equal(t, "Invalid username or password", cbResp.Callbacks[0].Error)

	//valid login and password
	cbReq.Callbacks[0].Value = "user1"
	cbReq.Callbacks[1].Value = "password"
	cbResp, err = f.Process(cbReq, nil, nil)
	assert.NoError(t, err)
	assert.True(t, len(cbResp.Callbacks) == 0)
	assert.Empty(t, cbResp.FlowId)
	assert.NotEmpty(t, cbResp.Token)
}

//TODO v0 add test with complex flow (2FA)
