package modules

import (
	"reflect"
	"regexp"

	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/models"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
)

type Credentials struct {
	BaseAuthModule
	primaryField      Field
	additinonalFields []Field
	credentialsState  *credentialsState
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

	//callbacks validation
	for i, cb := range inCbs {
		if cb.Value == "" && cbs[i].Required {
			(&cbs[i]).Error = (&cbs[i]).Prompt + " required"
			callbacksValid = false
		} else if cbs[i].Validation != "" {
			re, err := regexp.Compile(cbs[i].Validation)
			if err != nil {
				cm.l.Errorf("error compiling regex for callback %v", cb.Validation)
				return state.FAIL, nil, errors.Wrapf(err, "error compiling regex for callback %v", cb.Validation)
			}
			match := re.Match([]byte(cb.Value))
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

	for _, cb := range inCbs {
		if cb.Name == cm.primaryField.Name {
			cm.credentialsState.UserID = cb.Value
		} else {
			cm.credentialsState.Properties[cb.Name] = cb.Value
		}
	}
	cm.updateState()
	s.UserId = cm.credentialsState.UserID
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
	moduleUser := models.User{
		ID:         cm.credentialsState.UserID,
		Properties: cm.credentialsState.Properties,
	}
	ur := cm.realm.UserDataStore.Repo
	user, ok := ur.GetUser(moduleUser.ID)
	var err error
	if !ok {
		user, err = ur.CreateUser(moduleUser)
		if err != nil {
			return errors.Wrap(err, "error creating user")
		}
	} else {
		user.Properties = moduleUser.Properties
		err = ur.UpdateUser(user)
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
	var pf Field
	if pfProp, ok := base.Properties[keyPrimaryField]; ok {
		pfObj := reflect.ValueOf(pfProp)
		pfPtr := &Field{}
		_ = mapstructure.Decode(pfObj.Interface(), pfPtr)
		if pfPtr == nil {
			panic("registration module primary field not defined")
		}
		err := pfPtr.initField()
		if err != nil {
			panic(err)
		}
		pf = *pfPtr
	} else {
		pf = Field{
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

	cm := &Credentials{
		base,
		pf,
		nil,
		&cs,
	}

	if af, ok := base.Properties[keyAdditionalFields]; ok {
		afObj := reflect.ValueOf(af)
		afs := make([]Field, afObj.Len())
		for i := 0; i < afObj.Len(); i++ {
			adf := &Field{}
			_ = mapstructure.Decode(afObj.Index(i).Interface(), adf)
			err := adf.initField()
			if err != nil {
				panic(err)
			}
			afs[i] = *adf
		}
		cm.additinonalFields = afs
	}
	cbLen := len(cm.additinonalFields) + 1

	adcbs := make([]callbacks.Callback, cbLen)
	if cm.additinonalFields != nil {
		for i, af := range cm.additinonalFields {
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
	adcbs[0] = callbacks.Callback{
		Name:       pf.Name,
		Type:       callbacks.TypeText,
		Prompt:     pf.Prompt,
		Value:      "",
		Required:   true,
		Validation: pf.Validation,
	}

	(&cm.BaseAuthModule).Callbacks = adcbs
	return cm
}
