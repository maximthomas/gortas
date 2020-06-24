package controller

import (
	"encoding/json"
	"errors"
	"math/rand"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/authmodules"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/models"
	"github.com/maximthomas/gortas/pkg/repo"
	"github.com/sirupsen/logrus"
)

type LoginController struct {
	auth   config.Authentication
	sr     repo.SessionRepository
	sess   config.Session
	logger logrus.FieldLogger
}

func NewLoginController(config config.Config) *LoginController {
	logger := config.Logger.WithField("module", "LoginController")
	a := config.Authentication
	sess := config.Session
	sr := config.Session.DataStore.Repo
	return &LoginController{a, sr, sess, logger}
}

func (l LoginController) Login(realmId string, authChainId string, c *gin.Context) {
	if realm, ok := l.auth.Realms[realmId]; ok {
		if chain, ok := realm.AuthChains[authChainId]; ok {
			logrus.Info(chain)
			err := l.processAuthChain(chain, realm, c)
			if err != nil {
				l.logger.Errorf("error processing auth chain %v", err)
				c.JSON(400, gin.H{"error": err.Error()})
			}
		} else {
			c.JSON(404, gin.H{"error": "auth chain not found"})
		}
	} else {
		c.JSON(404, gin.H{"error": "Realm not found"})
	}
}

func (l LoginController) processAuthChain(authChain config.AuthChain, realm config.Realm, c *gin.Context) error {
	//get login session state from request, if there's no session state, create one
	lss := l.getLoginSessionState(authChain, realm, c)

	for moduleIndex, moduleInfo := range lss.Modules { //iterate modules in chain
		switch moduleInfo.State {
		case auth.Start, auth.InProgress:
			am, err := authmodules.GetAuthModule(moduleInfo, realm, l.sr)
			if err != nil {
				return err
			}
			var newState auth.ModuleState
			var cbs []models.Callback
			switch moduleInfo.State {
			case auth.Start:
				{
					newState, cbs, err = am.Process(lss, c)
					if err != nil {
						return err
					}
					break
				}
			case auth.InProgress:
				{
					var cbReq models.CallbackRequest
					err := c.ShouldBindJSON(&cbReq)
					if err != nil {
						l.logger.Error("error parsing request body: ", err)
						return errors.New("bad request")
					}
					err = am.ValidateCallbacks(cbReq.Callbacks)
					if err != nil {
						return err
					}
					newState, cbs, err = am.ProcessCallbacks(cbReq.Callbacks, lss, c)
					if err != nil {
						return err
					}
					break
				}
			}
			moduleInfo.State = newState

			lss.UpdateModuleInfo(moduleIndex, moduleInfo)
			err = l.updateLoginSessionState(lss)
			if err != nil {
				return err
			}

			switch moduleInfo.State {
			case auth.InProgress, auth.Start:
				cbReq := models.CallbackRequest{
					Callbacks: cbs,
					Module:    moduleInfo.Id,
				}
				c.SetCookie(auth.AuthCookieName, lss.SessionId, 0, "/", "", false, true)
				c.JSON(200, cbReq)
				return nil
			case auth.Pass:
				continue
			case auth.Fail:
				c.SetCookie(auth.AuthCookieName, "", 0, "/", "", false, true)
				c.JSON(401, gin.H{"status": "fail"})
				return nil
			}

		}
	}
	//if all modules passed authentication succeeded
	authSucceeded := true
	for _, moduleInfo := range lss.Modules {
		if moduleInfo.State != auth.Pass {
			authSucceeded = false
			break
		}
	}

	if authSucceeded {
		sessID, err := l.createSession(lss, realm)
		if err != nil {
			return err
		}

		for _, moduleInfo := range lss.Modules {
			am, err := authmodules.GetAuthModule(moduleInfo, realm, l.sr)
			if err != nil {
				return err
			}
			err = am.PostProcess(sessID, lss, c)
			if err != nil {
				return err
			}
		}

		c.SetCookie(auth.SessionCookieName, sessID, 0, "/", "", false, true)
		h := gin.H{"status": "success"}
		if lss.RedirectURI != "" {
			h["redirect_uri"] = lss.RedirectURI
		}
		c.JSON(200, h)
	}

	return nil
}

func getLoginSessionIdFromRequest(c *gin.Context) string {
	if c.Request.Method == "GET" { //for get request create new session
		return ""
	}
	sessionCookie, err := c.Request.Cookie(auth.AuthCookieName)
	if err == nil {
		return sessionCookie.Value
	}
	return ""
}

func (l LoginController) getLoginSessionState(authChain config.AuthChain, realm config.Realm, c *gin.Context) *auth.LoginSessionState {

	createNewSession := false
	var lss auth.LoginSessionState
	sessionId := getLoginSessionIdFromRequest(c)
	if sessionId == "" { //create mew session & login state
		createNewSession = true
	} else {
		session, err := l.sr.GetSession(sessionId)
		if err != nil {
			createNewSession = true
		} else {
			err = json.Unmarshal([]byte(session.Properties["lss"]), &lss)
			if err != nil {
				createNewSession = true
			}
		}
	}
	if createNewSession {
		lss = auth.LoginSessionState{
			Modules:     make([]auth.LoginSessionStateModuleInfo, len(authChain.Modules)),
			SharedState: make(map[string]string),
			UserId:      "",
			SessionId:   uuid.New().String(),
		}

		for i, chainModule := range authChain.Modules {
			lss.Modules[i].Id = chainModule.ID
			realmModule := realm.Modules[chainModule.ID]
			lss.Modules[i].Type = realmModule.Type
			lss.Modules[i].Properties = make(auth.LoginSessionStateModuleProperties)
			for k, v := range realmModule.Properties {
				lss.Modules[i].Properties[k] = v
			}
			for k, v := range chainModule.Properties {
				lss.Modules[i].Properties[k] = v
			}
			lss.Modules[i].SharedState = make(map[string]interface{})
		}
	}

	return &lss
}

func (l LoginController) updateLoginSessionState(lss *auth.LoginSessionState) error {
	sessionProp, err := json.Marshal(*lss)
	l.logger.Info(string(sessionProp))
	if err != nil {
		return err
	}
	session, err := l.sr.GetSession(lss.SessionId)
	if err != nil {
		session = models.Session{
			ID:         lss.SessionId,
			Properties: make(map[string]string),
		}
		session.Properties["lss"] = string(sessionProp)
		_, err = l.sr.CreateSession(session)
	} else {
		session.Properties["lss"] = string(sessionProp)
		err = l.sr.UpdateSession(session)
	}
	if err != nil {
		return err
	}
	return nil

}

func (l LoginController) createSession(lss *auth.LoginSessionState, realm config.Realm) (sessId string, err error) {
	sc := l.sess
	if lss.UserId == "" {
		return sessId, errors.New("user id is not set")
	}
	var user models.User
	user, userExists := realm.UserDataStore.Repo.GetUser(lss.UserId)

	var sessionID string
	if sc.Type == "stateless" {
		token := jwt.New(jwt.SigningMethodRS256)
		claims := token.Claims.(jwt.MapClaims)
		exp := time.Second * time.Duration(rand.Intn(sc.Expires))
		claims["exp"] = time.Now().Add(exp).Unix()
		claims["jti"] = sc.Jwt.PrivateKeyID
		claims["iat"] = time.Now().Unix()
		claims["iss"] = sc.Jwt.Issuer
		claims["sub"] = lss.UserId
		claims["realm"] = realm.ID
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
				"realm":  realm.ID,
			},
		}
		newSession, err = l.sr.CreateSession(newSession)
		if err != nil {
			return sessId, err
		}
	}
	return sessionID, nil
}
