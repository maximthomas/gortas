package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/constants"
	"github.com/maximthomas/gortas/pkg/auth/modules"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/log"
	"github.com/maximthomas/gortas/pkg/session"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	autherrors "github.com/maximthomas/gortas/pkg/auth/errors"
)

type FlowProcessor interface {
	Process(flowName string, cbReq callbacks.Request, r *http.Request, w http.ResponseWriter) (cbResp callbacks.Response, err error)
}

type flowProcessor struct {
	logger logrus.FieldLogger
}

func NewFlowProcessor() FlowProcessor {
	return &flowProcessor{
		logger: log.WithField("module", "FlowProcessor"),
	}
}

// Process responsible for the authentication process
// goes through flow state authentication modules, requests and processes callbacks
func (f *flowProcessor) Process(flowName string, cbReq callbacks.Request, r *http.Request, w http.ResponseWriter) (cbResp callbacks.Response, err error) {

	fs, err := f.getFlowState(flowName, cbReq.FlowID)
	if err != nil {
		return cbResp, fmt.Errorf("Process: error getting flow state %w", err)
	}
	// TODO extract process callbacks to a separate function

	inCbs := cbReq.Callbacks
	var outCbs []callbacks.Callback
modules:
	for moduleIndex, moduleInfo := range fs.Modules {
		switch moduleInfo.Status {
		// TODO v2 match module names in a callback request
		case state.Start, state.InProgress:
			var instance modules.AuthModule
			instance, err = modules.GetAuthModule(moduleInfo, r, w)
			if err != nil {
				return cbResp, fmt.Errorf("Process: error getting auth module %v %w", moduleInfo, err)
			}
			var newState state.ModuleStatus
			// if module is the first in the flow, then pass callbacks directly to the module
			if (len(cbReq.Callbacks) == 0 || moduleIndex > 0) && moduleInfo.Status == state.Start {
				newState, outCbs, err = instance.Process(&fs)
				if err != nil {
					return cbResp, err
				}
			} else {
				if err != nil {
					f.logger.Error("error parsing request body: ", err)
					return cbResp, errors.New("bad request")
				}
				err = instance.ValidateCallbacks(inCbs)
				if err != nil {
					return cbResp, err
				}
				newState, outCbs, err = instance.ProcessCallbacks(inCbs, &fs)
				if err != nil {
					return cbResp, err
				}
			}

			moduleInfo.Status = newState

			fs.UpdateModuleInfo(moduleIndex, moduleInfo)
			err = f.updateFlowState(&fs)
			if err != nil {
				return cbResp, errors.Wrap(err, "error update flowstate")
			}

			switch moduleInfo.Status {
			case state.InProgress, state.Start:
				cbResp = callbacks.Response{
					Callbacks: outCbs,
					Module:    moduleInfo.ID,
					FlowID:    fs.ID,
				}
				return cbResp, err
			case state.Pass:
				if moduleInfo.Criteria == constants.CriteriaSufficient { // TODO v2 refactor move to function
					break modules
				}
				continue
			case state.Fail:
				if moduleInfo.Criteria == constants.CriteriaSufficient { // TODO v2 refactor move to function
					continue
				}
				return cbResp, autherrors.NewAuthFailed("auth failed")
			}
		}
	}
	authSucceeded := true
	for _, moduleInfo := range fs.Modules {

		if moduleInfo.Criteria == constants.CriteriaSufficient { // TODO v2 refactor move to function
			if moduleInfo.Status == state.Pass {
				break
			}
		} else if moduleInfo.Status != state.Pass {
			authSucceeded = false
			break
		}
	}

	if authSucceeded {
		for _, moduleInfo := range fs.Modules {
			var am modules.AuthModule
			am, err = modules.GetAuthModule(moduleInfo, r, w)
			if err != nil {
				return cbResp, errors.Wrap(err, "error getting auth module for postprocess")
			}
			err = am.PostProcess(&fs)
			if err != nil {
				return cbResp, errors.Wrap(err, "error while postprocess")
			}
		}

		var sessID string
		sessID, err = f.createSession(&fs)
		if err != nil {
			return cbResp, errors.Wrap(err, "error creating session")
		}
		cbResp = callbacks.Response{
			Token: sessID,
			Type:  "Bearer",
		}
		err = session.GetSessionService().DeleteSession(fs.ID)
		if err != nil {
			f.logger.Warnf("error clearing session %s %v", fs.ID, err)
		}

		return cbResp, err
	}

	return cbResp, err
}

func (f *flowProcessor) createSession(fs *state.FlowState) (sessID string, err error) {
	if fs.UserID == "" {
		return sessID, errors.New("user id is not set")
	}

	return session.GetSessionService().CreateUserSession(fs.UserID)

}

func (f *flowProcessor) updateFlowState(fs *state.FlowState) error {
	sessionProp, err := json.Marshal(*fs)
	if err != nil {
		return errors.Wrap(err, "error marshaling flow sate")
	}

	ss := session.GetSessionService()

	sess, err := ss.GetSession(fs.ID)
	if err != nil {
		sess = session.Session{
			ID:         fs.ID,
			Properties: make(map[string]string),
		}
		sess.Properties[constants.FlowStateSessionProperty] = string(sessionProp)
		_, err = ss.CreateSession(sess)
	} else {
		sess.Properties[constants.FlowStateSessionProperty] = string(sessionProp)
		err = ss.UpdateSession(sess)
	}
	if err != nil {
		return err
	}
	return nil

}

func (f *flowProcessor) getFlowState(name, id string) (state.FlowState, error) {
	c := config.GetConfig()
	ss := session.GetSessionService()
	sess, err := ss.GetSession(id)
	var fs state.FlowState
	if err != nil {
		flow, ok := c.Flows[name]
		if !ok {
			return fs, errors.Errorf("auth flow %v not found", name)
		}
		fs = f.newFlowState(name, flow)
	} else {
		err = json.Unmarshal([]byte(sess.Properties[constants.FlowStateSessionProperty]), &fs)
		if err != nil {
			return fs, errors.New("session property fs does not exsit")
		}
	}

	return fs, nil
}

// createNewFlowState - creates new flow state from the Realm and AuthFlow settings, generates new flow Id and fill module properties
func (f *flowProcessor) newFlowState(flowName string, flow config.Flow) state.FlowState {

	fs := state.FlowState{
		Modules:     make([]state.FlowStateModuleInfo, len(flow.Modules)),
		SharedState: make(map[string]string),
		UserID:      "",
		ID:          uuid.New().String(),
		Name:        flowName,
	}

	for i, module := range flow.Modules {
		fs.Modules[i].ID = module.ID
		fs.Modules[i].Type = module.Type
		fs.Modules[i].Properties = make(state.FlowStateModuleProperties)
		for k, v := range module.Properties {
			fs.Modules[i].Properties[k] = v
		}
		for k, v := range module.Properties {
			fs.Modules[i].Properties[k] = v
		}
		fs.Modules[i].State = make(map[string]interface{})
		fs.Modules[i].Criteria = module.Criteria
	}
	return fs
}
