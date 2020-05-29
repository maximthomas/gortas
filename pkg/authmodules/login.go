package authmodules

import (
	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/models"
)

type LoginPassword struct {
	BaseAuthModule
}

func (lm *LoginPassword) Init(c *gin.Context) error {
	return nil
}

func (lm *LoginPassword) Process(lss *auth.LoginSessionState, c *gin.Context) (ms auth.ModuleState, cbs []models.Callback, err error) {
	return auth.InProgress, lm.callbacks, err
}

func (lm *LoginPassword) ProcessCallbacks(inCbs []models.Callback, lss *auth.LoginSessionState, c *gin.Context) (ms auth.ModuleState, cbs []models.Callback, err error) {
	var username string
	var password string

	for _, cb := range inCbs {
		switch cb.Name {
		case "login":
			username = cb.Value
			break
		case "password":
			password = cb.Value
		}
	}

	valid := lm.r.UserDataStore.Repo.ValidatePassword(username, password)
	if valid {
		lss.UserId = username
		return auth.Pass, cbs, err
	} else {
		cbs = lm.callbacks
		(&cbs[0]).Error = "Invalid username or password"
		return auth.InProgress, cbs, err
	}
}

func (lm *LoginPassword) ValidateCallbacks(cbs []models.Callback) error {
	return lm.BaseAuthModule.ValidateCallbacks(cbs)
}

func NewLoginModule(base BaseAuthModule) *LoginPassword {
	(&base).callbacks = []models.Callback{
		{
			Name:   "login",
			Type:   "text",
			Prompt: "Login",
			Value:  "",
		},
		{
			Name:   "password",
			Type:   "password",
			Prompt: "Password",
			Value:  "",
		},
	}
	return &LoginPassword{
		base,
	}
}
