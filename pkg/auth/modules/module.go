package modules

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/repo"
	"github.com/sirupsen/logrus"
)

type AuthModule interface {
	Process(s *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error)
	ProcessCallbacks(inCbs []callbacks.Callback, s *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error)
	ValidateCallbacks(cbs []callbacks.Callback) error
	PostProcess(fs *state.FlowState) error
}

type Field struct {
	Name       string
	Prompt     string
	Required   bool
	Validation string
}

var modulesRegistry = &sync.Map{}

func RegisterModule(mt string, constructor func(BaseAuthModule) AuthModule) {
	logrus.Infof("registered %v module", mt)
	modulesRegistry.Store(mt, constructor)
}

type moduleConstructor = func(base BaseAuthModule) AuthModule

func GetAuthModule(mi state.FlowStateModuleInfo, realm config.Realm, req *http.Request, w http.ResponseWriter) (AuthModule, error) {
	base := BaseAuthModule{
		Properties: mi.Properties,
		realm:      realm,
		State:      mi.State,
		req:        req,
		w:          w,
	}
	constructor, ok := modulesRegistry.Load(mi.Type)
	if !ok {
		return nil, fmt.Errorf("module %v does not exists", mi.Type)
	}
	if c, ok := constructor.(moduleConstructor); ok {
		return moduleConstructor(c)(base), nil
	}
	return nil, fmt.Errorf("error converting %v to module constructor", constructor)
}

type BaseAuthModule struct {
	Properties map[string]interface{}
	realm      config.Realm
	Callbacks  []callbacks.Callback
	State      map[string]interface{}
	req        *http.Request
	w          http.ResponseWriter
}

func (b BaseAuthModule) getUserRepo() repo.UserRepository {
	return b.realm.UserDataStore.Repo
}

func (b BaseAuthModule) ValidateCallbacks(cbs []callbacks.Callback) error {
	err := fmt.Errorf("callbacks does not match %v %v", b.Callbacks, cbs)
	if len(cbs) == len(b.Callbacks) {
		for i := range cbs {
			if cbs[i].Name != b.Callbacks[i].Name {
				return err
			}
		}
		return nil
	}
	return err
}
