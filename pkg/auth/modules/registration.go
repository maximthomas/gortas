package modules

import (
	"regexp"

	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/user"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
)

// TODO add password format
// TODO add confirmation password callback
type Registration struct {
	BaseAuthModule
	PrimaryField      Field
	UsePassword       bool
	UseRepeatPassword bool
	AdditionalFields  []Field
}

func (f *Field) initField() error {
	if f.Validation == "" {
		return nil
	}
	_, err := regexp.Compile(f.Validation)
	if err != nil {
		return err
	}
	return nil
}

func (rm *Registration) Process(_ *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {
	return state.IN_PROGRESS, rm.Callbacks, err
}

func (rm *Registration) ProcessCallbacks(inCbs []callbacks.Callback, fs *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {
	if inCbs == nil {
		return state.FAIL, cbs, errors.New("callbacks can't be nil")
	}
	callbacksValid := true
	errCbs := make([]callbacks.Callback, len(rm.Callbacks))
	copy(errCbs, rm.Callbacks)

	for i, cb := range inCbs {
		if cb.Value == "" && errCbs[i].Required {
			(&errCbs[i]).Error = (&errCbs[i]).Prompt + " required"
			callbacksValid = false
		} else if errCbs[i].Validation != "" {
			var re *regexp.Regexp
			re, err = regexp.Compile(errCbs[i].Validation)
			if err != nil {
				rm.l.Errorf("error compiling regex for callback %v", cb.Validation)
				return state.FAIL, cbs, errors.Wrapf(err, "error compiling regex for callback %v", cb.Validation)
			}
			match := re.MatchString(cb.Value)
			if !match {
				(&errCbs[i]).Error = (&errCbs[i]).Prompt + " invalid"
				callbacksValid = false
			}
		}
	}

	if !callbacksValid {
		return state.IN_PROGRESS, errCbs, nil
	}

	var username string
	var password string
	var repeatPassword string

	fields := make(map[string]string, len(inCbs)-2)

	for _, cb := range inCbs {
		switch cb.Name {
		case rm.PrimaryField.Name:
			username = cb.Value
		case "password":
			password = cb.Value
		case "repeatPassword":
			repeatPassword = cb.Value
		default:
			fields[cb.Name] = cb.Value
		}
	}

	if repeatPassword != password {
		(&errCbs[len(inCbs)-1]).Error = "Passwords do not match"
		return state.IN_PROGRESS, errCbs, nil
	}

	us := user.GetUserService()
	_, exists := us.GetUser(username)
	if exists {
		(&errCbs[0]).Error = "User exists"
		return state.IN_PROGRESS, errCbs, nil
	}

	u := user.User{
		ID:         username,
		Properties: fields,
	}

	_, err = us.CreateUser(u)
	if err != nil {
		return state.FAIL, cbs, err
	}

	err = us.SetPassword(u.ID, password)
	if err != nil {
		return state.FAIL, cbs, err
	}

	fs.UserID = u.ID

	return state.PASS, rm.Callbacks, err
}

func (rm *Registration) ValidateCallbacks(cbs []callbacks.Callback) error {
	return rm.BaseAuthModule.ValidateCallbacks(cbs)
}

func (rm *Registration) PostProcess(_ *state.FlowState) error {
	return nil
}

func init() {
	RegisterModule("registration", newRegistrationModule)
}

func newRegistrationModule(base BaseAuthModule) AuthModule {
	var rm Registration
	rm.UsePassword = true //default value
	rm.UseRepeatPassword = true
	err := mapstructure.Decode(base.Properties, &rm)
	if err != nil {
		panic(err) //TODO add error processing
	}
	rm.BaseAuthModule = base

	cbLen := len(rm.AdditionalFields) + 1
	if rm.UsePassword {
		cbLen++
	}

	if rm.UseRepeatPassword {
		cbLen++
	}

	adcbs := make([]callbacks.Callback, cbLen)
	if rm.AdditionalFields != nil {
		for i, af := range rm.AdditionalFields {
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
		Name:       rm.PrimaryField.Name,
		Type:       callbacks.TypeText,
		Prompt:     rm.PrimaryField.Prompt,
		Value:      "",
		Required:   true,
		Validation: rm.PrimaryField.Validation,
	}
	if rm.UsePassword {
		adcbs[cbLen-2] = callbacks.Callback{
			Name:     "password",
			Type:     callbacks.TypePassword,
			Prompt:   "Password",
			Value:    "",
			Required: true,
		}
	}
	if rm.UseRepeatPassword {
		adcbs[cbLen-1] = callbacks.Callback{
			Name:     "repeatPassword",
			Type:     callbacks.TypePassword,
			Prompt:   "Repeat password",
			Value:    "",
			Required: true,
		}
	}

	(&rm.BaseAuthModule).Callbacks = adcbs
	return &rm
}
