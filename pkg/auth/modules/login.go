package modules

import (
	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/user"
)

type LoginPassword struct {
	BaseAuthModule
}

func (lm *LoginPassword) Process(_ *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {
	return state.IN_PROGRESS, lm.Callbacks, err
}

func (lm *LoginPassword) ProcessCallbacks(inCbs []callbacks.Callback, fs *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {
	var username string
	var password string

	for _, cb := range inCbs {
		switch cb.Name {
		case "login":
			username = cb.Value
		case "password":
			password = cb.Value
		}
	}
	ur := user.GetUserService().Repo
	valid := ur.ValidatePassword(username, password)
	if valid {
		fs.UserId = username
		return state.PASS, cbs, err
	} else {
		cbs = lm.Callbacks
		(&cbs[0]).Error = "Invalid username or password"
		return state.IN_PROGRESS, cbs, err
	}
}

func (lm *LoginPassword) ValidateCallbacks(cbs []callbacks.Callback) error {
	return lm.BaseAuthModule.ValidateCallbacks(cbs)
}

func (lm *LoginPassword) PostProcess(_ *state.FlowState) error {
	return nil
}

func init() {
	RegisterModule("login", newLoginPassword)
}

func newLoginPassword(base BaseAuthModule) AuthModule {
	(&base).Callbacks = []callbacks.Callback{
		{
			Name:     "login",
			Type:     callbacks.TypeText,
			Prompt:   "Login",
			Value:    "",
			Required: true,
		},
		{
			Name:     "password",
			Type:     callbacks.TypePassword,
			Prompt:   "Password",
			Value:    "",
			Required: true,
		},
	}
	return &LoginPassword{
		base,
	}
}
