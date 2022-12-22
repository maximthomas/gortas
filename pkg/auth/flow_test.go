package auth

import (
	"testing"

	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/constants"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/session"

	"github.com/maximthomas/gortas/pkg/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const testFlowId = "test-flow-id"
const corruptedFlowId = "corrupted-flow-id"

func init() {
	logger := logrus.New()
	flows := map[string]config.Flow{
		"login": {Modules: []config.Module{
			{
				ID:   "login",
				Type: "login",
			},
		}},
		"register": {Modules: []config.Module{
			{
				ID: "registration",
				Properties: map[string]interface{}{
					"testProp": "testVal",
					"additionalFields": []map[interface{}]interface{}{{
						"dataStore": "name",
						"prompt":    "Name",
					},
					},
				},
			},
		},
		},
		"sso": {Modules: []config.Module{}},
	}

	conf := config.Config{
		Flows:  flows,
		Logger: logger,
		Session: session.SessionConfig{
			Type: "stateful",
		},
	}
	config.SetConfig(conf)

	s := session.Session{
		ID: testFlowId,
		Properties: map[string]string{
			constants.FlowStateSessionProperty: "{}",
		},
	}
	_, _ = session.GetSessionService().CreateSession(s)
	corruptedSession := session.Session{
		ID: corruptedFlowId,
		Properties: map[string]string{
			constants.FlowStateSessionProperty: "bad",
		},
	}
	_, _ = session.GetSessionService().CreateSession(corruptedSession)
}

func TestGetFlowState(t *testing.T) {
	fp := flowProcessor{}
	tests := []struct {
		name       string
		realm      string
		flowName   string
		flowId     string
		checkError func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool
		checkFlow  func(t assert.TestingT, fs state.FlowState)
	}{
		{name: "existing flow", flowName: "login", checkError: assert.NoError, checkFlow: func(t assert.TestingT, fs state.FlowState) { assert.NotNil(t, fs) }},
		{name: "non existing flow", flowName: "bad", checkError: assert.Error, checkFlow: func(t assert.TestingT, fs state.FlowState) { assert.True(t, fs.Id == "") }},
		{name: "existing flowId", flowId: testFlowId, checkError: assert.NoError, checkFlow: func(t assert.TestingT, fs state.FlowState) { assert.NotNil(t, fs) }},
		{name: "corrupted flowId", flowId: corruptedFlowId, checkError: assert.Error, checkFlow: func(t assert.TestingT, fs state.FlowState) { assert.True(t, fs.Id == "") }},
		{name: "non existing flowId", flowName: "login", flowId: "bad-flow-id", checkError: assert.NoError, checkFlow: func(t assert.TestingT, fs state.FlowState) { assert.NotNil(t, fs) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, err := fp.getFlowState(tt.flowName, tt.flowId)
			tt.checkError(t, err)
			tt.checkFlow(t, fs)
		})
	}
}

func TestProcess(t *testing.T) {
	fp := NewFlowProcessor()
	var cbReq callbacks.Request
	cbResp, err := fp.Process("login", cbReq, nil, nil)
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
	cbReq.FlowId = cbResp.FlowId
	cbResp, err = fp.Process("login", cbReq, nil, nil)
	assert.NoError(t, err)
	assert.True(t, len(cbResp.Callbacks) > 0)
	assert.Equal(t, "login", cbResp.Module)
	assert.NotEmpty(t, cbResp.FlowId)
	assert.Equal(t, "Invalid username or password", cbResp.Callbacks[0].Error)

	//valid login and password
	cbReq.Callbacks[0].Value = "user1"
	cbReq.Callbacks[1].Value = "password"
	cbResp, err = fp.Process("login", cbReq, nil, nil)
	assert.NoError(t, err)
	assert.True(t, len(cbResp.Callbacks) == 0)
	assert.Empty(t, cbResp.FlowId)
	assert.NotEmpty(t, cbResp.Token)
}

//TODO v0 add test with complex flow (2FA)
