package authmodules

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/models"
	"github.com/maximthomas/gortas/pkg/repo"
)

type AuthModule interface {
	Process(s *auth.LoginSessionState, c *gin.Context) (ms auth.ModuleState, cbs []models.Callback, err error)
	ProcessCallbacks(inCbs []models.Callback, s *auth.LoginSessionState, c *gin.Context) (ms auth.ModuleState, cbs []models.Callback, err error)
	ValidateCallbacks(cbs []models.Callback) error
	PostProcess(sessID string, lss *auth.LoginSessionState, c *gin.Context) error
}

func GetAuthModule(mi auth.LoginSessionStateModuleInfo, r config.Realm, sr repo.SessionRepository) (AuthModule, error) {
	base := BaseAuthModule{
		properties:  mi.Properties,
		r:           r,
		sr:          sr,
		sharedState: mi.SharedState,
	}
	switch mi.Type {
	case "login":
		return NewLoginModule(base), nil
	case "registration":
		return NewRegistrationModule(base), nil
	case "kerberos":
		return NewKerberosModule(base), nil
	case "hydra":
		return NewHydraModule(base), nil
	case "qr":
		return NewQRModule(base), nil
	default:
		return nil, errors.New("module does not exists")
	}
}

type BaseAuthModule struct {
	properties  map[string]interface{}
	r           config.Realm
	sr          repo.SessionRepository
	callbacks   []models.Callback
	sharedState map[string]interface{}
}

func (b BaseAuthModule) ValidateCallbacks(cbs []models.Callback) error {
	err := errors.New("callbacks does not match")
	if len(cbs) == len(b.callbacks) {
		for i := range cbs {
			if cbs[i].Name != cbs[i].Name {
				return err
			}
		}
		return nil
	}
	return err
}
