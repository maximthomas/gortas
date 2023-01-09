package modules

import (
	"testing"

	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/stretchr/testify/assert"
)

type SimpleModule struct {
	BaseAuthModule
}

func (sm *SimpleModule) Process(_ *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {
	return state.IN_PROGRESS, sm.Callbacks, err
}

func (sm *SimpleModule) ProcessCallbacks(inCbs []callbacks.Callback, fs *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {
	return state.IN_PROGRESS, sm.Callbacks, err
}

func (sm *SimpleModule) ValidateCallbacks(cbs []callbacks.Callback) error {
	return sm.BaseAuthModule.ValidateCallbacks(cbs)
}

func (sm *SimpleModule) PostProcess(_ *state.FlowState) error {
	return nil
}

func init() {
	RegisterModule("simple", newSimpleModule)
}

func newSimpleModule(base BaseAuthModule) AuthModule {
	return &SimpleModule{
		base,
	}
}

func TestModuleRegistered(t *testing.T) {
	constructor, ok := modulesRegistry.Load("simple")
	assert.True(t, ok)

	_, ok = constructor.(moduleConstructor)
	assert.True(t, ok)
}

func TestGetModuleFromRegistry(t *testing.T) {
	config.SetConfig(config.Config{})
	mi := state.FlowStateModuleInfo{
		ID:   "simple",
		Type: "simple",
	}
	m, err := GetAuthModule(mi, nil, nil)
	assert.NoError(t, err)

	_, ok := m.(*SimpleModule)
	assert.True(t, ok)
}
