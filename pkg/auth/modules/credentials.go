package modules

import (
	"regexp"

	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/user"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
)

type Credentials struct {
	BaseAuthModule
	PrimaryField     Field
	AdditionalFields []Field
	credentialsState *credentialsState
}

type credentialsState struct {
	UserID     string
	Properties map[string]string
}

func (cm *Credentials) Process(s *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {
	return state.IN_PROGRESS, cm.Callbacks, nil
}

func (cm *Credentials) ProcessCallbacks(inCbs []callbacks.Callback, s *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {
	cbs = make([]callbacks.Callback, len(cm.Callbacks))
	copy(cbs, cm.Callbacks)

	callbacksValid := true

	// callbacks validation
	for i, cb := range inCbs {
		if cb.Value == "" && cbs[i].Required {
			(&cbs[i]).Error = (&cbs[i]).Prompt + " required"
			callbacksValid = false
		} else if cbs[i].Validation != "" {
			var re *regexp.Regexp
			re, err = regexp.Compile(cbs[i].Validation)
			if err != nil {
				cm.l.Errorf("error compiling regex for callback %v", cb.Validation)
				return state.FAIL, nil, errors.Wrapf(err, "error compiling regex for callback %v", cb.Validation)
			}
			match := re.MatchString(cb.Value)
			if !match {
				(&cbs[i]).Error = (&cbs[i]).Prompt + " invalid"
				callbacksValid = false
			}
		}
	}

	if !callbacksValid {
		return state.IN_PROGRESS, cbs, err
	}

	//fill state values

	for i := range inCbs {
		cb := inCbs[i]
		if cb.Name == cm.PrimaryField.Name {
			cm.credentialsState.UserID = cb.Value
		} else {
			cm.credentialsState.Properties[cb.Name] = cb.Value
		}
	}
	cm.updateState()
	s.UserID = cm.credentialsState.UserID
	return state.PASS, nil, err
}

func (cm *Credentials) updateState() {
	cm.State["userId"] = cm.credentialsState.UserID
	cm.State["properties"] = cm.credentialsState.Properties
}

func (cm *Credentials) ValidateCallbacks(cbs []callbacks.Callback) error {
	return cm.BaseAuthModule.ValidateCallbacks(cbs)
}

func (cm *Credentials) PostProcess(fs *state.FlowState) error {
	moduleUser := user.User{
		ID:         cm.credentialsState.UserID,
		Properties: cm.credentialsState.Properties,
	}
	us := user.GetUserService()
	u, ok := us.GetUser(moduleUser.ID)
	var err error
	if !ok {
		u, err = us.CreateUser(moduleUser)
		if err != nil {
			return errors.Wrap(err, "error creating user")
		}
	} else {
		u.Properties = moduleUser.Properties
		err = us.UpdateUser(u)
		if err != nil {
			return errors.Wrap(err, "error updating user")
		}
	}

	return nil
}

func init() {
	RegisterModule("credentials", newCredentials)
}

func newCredentials(base BaseAuthModule) AuthModule {
	var cm Credentials
	err := mapstructure.Decode(base.Properties, &cm)
	if err != nil {
		panic(err) //TODO add error processing
	}

	if cm.PrimaryField.Name == "" {
		cm.PrimaryField = Field{
			Name:     "login",
			Prompt:   "Login",
			Required: true,
		}
	}
	cs := credentialsState{
		UserID:     "",
		Properties: make(map[string]string),
	}
	_ = mapstructure.Decode(base.State, &cs)

	cm.BaseAuthModule = base
	cm.credentialsState = &cs

	cbLen := len(cm.AdditionalFields) + 1

	adcbs := make([]callbacks.Callback, cbLen)
	if cm.AdditionalFields != nil {
		for i, af := range cm.AdditionalFields {
			adcbs[i+1] = callbacks.Callback{
				Name:       af.Name,
				Type:       callbacks.TypeText,
				Value:      "",
				Prompt:     af.Prompt,
				Required:   af.Required,
				Validation: af.Validation,
			}
		}
	}
	pf := cm.PrimaryField
	adcbs[0] = callbacks.Callback{
		Name:       pf.Name,
		Type:       callbacks.TypeText,
		Prompt:     pf.Prompt,
		Value:      "",
		Required:   true,
		Validation: pf.Validation,
	}

	(&cm.BaseAuthModule).Callbacks = adcbs
	return &cm
}
