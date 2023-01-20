package auth

import (
	"testing"

	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/constants"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/session"

	"github.com/maximthomas/gortas/pkg/config"
	"github.com/stretchr/testify/assert"
)

const testFlowID = "test-flow-id"
const corruptedFlowID = "corrupted-flow-id"

func init() {
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
		Flows: flows,
		Session: session.Config{
			Type: "stateful",
		},
	}
	config.SetConfig(&conf)

	s := session.Session{
		ID: testFlowID,
		Properties: map[string]string{
			constants.FlowStateSessionProperty: "{}",
		},
	}
	_, _ = session.GetSessionService().CreateSession(s)
	corruptedSession := session.Session{
		ID: corruptedFlowID,
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
		flowID     string
		checkError func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool
		checkFlow  func(t assert.TestingT, fs state.FlowState)
	}{
		{name: "existing flow", flowName: "login", checkError: assert.NoError,
			checkFlow: func(t assert.TestingT, fs state.FlowState) { assert.NotNil(t, fs) }},
		{name: "non existing flow", flowName: "bad", checkError: assert.Error,
			checkFlow: func(t assert.TestingT, fs state.FlowState) { assert.True(t, fs.ID == "") }},
		{name: "existing flowId", flowID: testFlowID, checkError: assert.NoError,
			checkFlow: func(t assert.TestingT, fs state.FlowState) { assert.NotNil(t, fs) }},
		{name: "corrupted flowId", flowID: corruptedFlowID, checkError: assert.Error,
			checkFlow: func(t assert.TestingT, fs state.FlowState) { assert.True(t, fs.ID == "") }},
		{name: "non existing flowId", flowName: "login", flowID: "bad-flow-id",
			checkError: assert.NoError, checkFlow: func(t assert.TestingT, fs state.FlowState) { assert.NotNil(t, fs) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, err := fp.getFlowState(tt.flowName, tt.flowID)
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
	assert.NotEmpty(t, cbResp.FlowID)

	//invalid login and password
	cbReq = callbacks.Request{
		Module:    cbResp.Module,
		Callbacks: cbResp.Callbacks,
	}
	cbReq.Callbacks[0].Value = "test"
	cbReq.Callbacks[1].Value = "test"
	cbReq.FlowID = cbResp.FlowID
	cbResp, err = fp.Process("login", cbReq, nil, nil)
	assert.NoError(t, err)
	assert.True(t, len(cbResp.Callbacks) > 0)
	assert.Equal(t, "login", cbResp.Module)
	assert.NotEmpty(t, cbResp.FlowID)
	assert.Equal(t, "Invalid username or password", cbResp.Callbacks[0].Error)

	//valid login and password
	cbReq.Callbacks[0].Value = "user1"
	cbReq.Callbacks[1].Value = "password"
	cbResp, err = fp.Process("login", cbReq, nil, nil)
	assert.NoError(t, err)
	assert.True(t, len(cbResp.Callbacks) == 0)
	assert.Empty(t, cbResp.FlowID)
	assert.NotEmpty(t, cbResp.Token)
}

//TODO v0 add test with complex flow (2FA)
