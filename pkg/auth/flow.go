package auth

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/google/uuid"
	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/constants"
	"github.com/maximthomas/gortas/pkg/auth/modules"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/models"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	autherrors "github.com/maximthomas/gortas/pkg/auth/errors"
)

type Flow struct {
	fs     state.FlowState
	logger logrus.FieldLogger
}

//Process responsible for the authentication process
//goes through flow state authentication modules, requests and processes callbacks
func (f *Flow) Process(cbReq callbacks.Request, r *http.Request, w http.ResponseWriter) (cbResp callbacks.Response, err error) {
	conf := config.GetConfig()
	inCbs := cbReq.Callbacks
	var outCbs []callbacks.Callback
modules:
	for moduleIndex, moduleInfo := range f.fs.Modules {
		switch moduleInfo.Status {
		// TODO v2 match module names in a callback request
		case state.START, state.IN_PROGRESS:
			instance, err := modules.GetAuthModule(moduleInfo, r, w)
			if err != nil {
				return cbResp, errors.Wrapf(err, "error getting auth module %v", moduleInfo)
			}
			var newState state.ModuleStatus

			switch moduleInfo.Status {
			case state.START:
				{
					newState, outCbs, err = instance.Process(&f.fs)
					if err != nil {
						return cbResp, err
					}
					break
				}
			case state.IN_PROGRESS:
				{
					if err != nil {
						f.logger.Error("error parsing request body: ", err)
						return cbResp, errors.New("bad request")
					}
					err = instance.ValidateCallbacks(inCbs)
					if err != nil {
						return cbResp, err
					}
					newState, outCbs, err = instance.ProcessCallbacks(inCbs, &f.fs)
					if err != nil {
						return cbResp, err
					}
					break
				}
			}
			moduleInfo.Status = newState

			f.fs.UpdateModuleInfo(moduleIndex, moduleInfo)
			err = updateFlowState(&f.fs)
			if err != nil {
				return cbResp, errors.Wrap(err, "error update flowstate")
			}

			switch moduleInfo.Status {
			case state.IN_PROGRESS, state.START:
				cbResp := callbacks.Response{
					Callbacks: outCbs,
					Module:    moduleInfo.Id,
					FlowId:    f.fs.Id,
				}
				return cbResp, err
			case state.PASS:
				if moduleInfo.Criteria == constants.CriteriaSufficient { //TODO v2 refactor move to function
					break modules
				}
				continue
			case state.FAIL:
				if moduleInfo.Criteria == constants.CriteriaSufficient { //TODO v2 refactor move to function
					continue
				}
				return cbResp, autherrors.NewAuthFailed("auth failed")
			}
		}
	}
	authSucceeded := true
	for _, moduleInfo := range f.fs.Modules {

		if moduleInfo.Criteria == constants.CriteriaSufficient { //TODO v2 refactor move to function
			if moduleInfo.Status == state.PASS {
				break
			}
		} else if moduleInfo.Status != state.PASS {
			authSucceeded = false
			break
		}
	}

	if authSucceeded {
		for _, moduleInfo := range f.fs.Modules {
			am, err := modules.GetAuthModule(moduleInfo, r, w)
			if err != nil {
				return cbResp, errors.Wrap(err, "error getting auth module for postprocess")
			}
			err = am.PostProcess(&f.fs)
			if err != nil {
				return cbResp, errors.Wrap(err, "error while postprocess")
			}
		}

		sessID, err := f.createSession()
		if err != nil {
			return cbResp, errors.Wrap(err, "error creating session")
		}
		cbResp = callbacks.Response{
			Token: sessID,
			Type:  "Bearer",
		}
		err = conf.Session.DataStore.Repo.DeleteSession(f.fs.Id)
		if err != nil {
			f.logger.Warnf("error clearing session %s %v", f.fs.Id, err)
		}

		return cbResp, err
	}

	return
}

func (f *Flow) createSession() (sessId string, err error) {
	sc := config.GetConfig().Session
	if f.fs.UserId == "" {
		return sessId, errors.New("user id is not set")
	}

	user, userExists := config.GetConfig().UserDataStore.Repo.GetUser(f.fs.UserId)

	var sessionID string
	if sc.Type == "stateless" {
		token := jwt.New(jwt.SigningMethodRS256)
		claims := token.Claims.(jwt.MapClaims)
		exp := time.Second * time.Duration(rand.Intn(sc.Expires))
		claims["exp"] = time.Now().Add(exp).Unix()
		claims["jti"] = sc.Jwt.PrivateKeyID
		claims["iat"] = time.Now().Unix()
		claims["iss"] = sc.Jwt.Issuer
		claims["sub"] = f.fs.UserId
		if userExists {
			claims["props"] = user.Properties
		}

		token.Header["jks"] = sc.Jwt.PrivateKeyID
		ss, _ := token.SignedString(sc.Jwt.PrivateKey)
		sessionID = ss
	} else {
		sessionID = uuid.New().String()
		newSession := models.Session{
			ID: sessionID,
			Properties: map[string]string{
				"userId": user.ID,
				"sub":    user.ID,
			},
		}
		for k, v := range user.Properties {
			newSession.Properties[k] = v
		}

		newSession, err = sc.DataStore.Repo.CreateSession(newSession)
		if err != nil {
			return sessId, err
		}
	}
	return sessionID, nil
}

func updateFlowState(fs *state.FlowState) error {
	sessionProp, err := json.Marshal(*fs)
	if err != nil {
		return errors.Wrap(err, "error marshalling flow sate")
	}

	sr := config.GetConfig().Session.DataStore.Repo

	session, err := sr.GetSession(fs.Id)
	if err != nil {
		session = models.Session{
			ID:         fs.Id,
			Properties: make(map[string]string),
		}
		session.Properties[constants.FlowStateSessionProperty] = string(sessionProp)
		_, err = sr.CreateSession(session)
	} else {
		session.Properties[constants.FlowStateSessionProperty] = string(sessionProp)
		err = sr.UpdateSession(session)
	}
	if err != nil {
		return err
	}
	return nil

}

func GetFlow(name string, id string) (*Flow, error) {
	c := config.GetConfig()
	sds := c.Session.DataStore
	session, err := sds.Repo.GetSession(id)
	var fs state.FlowState
	if err != nil {
		flow, ok := c.Flows[name]
		if !ok {
			return nil, errors.Errorf("auth flow %v not found", name)
		}
		fs = createNewFlowState(name, flow)
	} else {
		err = json.Unmarshal([]byte(session.Properties[constants.FlowStateSessionProperty]), &fs)
		if err != nil {
			return nil, errors.New("session property fs does not exsit")
		}
	}

	return &Flow{
		fs:     fs,
		logger: c.Logger.WithField("module", "Flow"),
	}, nil
}

// createNewFlowState - creates new flow state from the Realm and AuthFlow settings, generates new flow Id and fill module properties
func createNewFlowState(flowName string, flow config.Flow) state.FlowState {

	fs := state.FlowState{
		Modules:     make([]state.FlowStateModuleInfo, len(flow.Modules)),
		SharedState: make(map[string]string),
		UserId:      "",
		Id:          uuid.New().String(),
		Name:        flowName,
	}

	for i, module := range flow.Modules {
		fs.Modules[i].Id = module.ID
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
