package controller

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"strings"
)

type SessionController struct {
	logger logrus.FieldLogger
}

func (sc *SessionController) SessionInfo(c *gin.Context) {
	var sessionId string
	authHeader := c.Request.Header.Get("Authorization")
	if authHeader != "" { //from header
		sessionId = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if sessionId == "" { //from cookie
		cookie, err := c.Request.Cookie(state.SessionCookieName)
		if err == nil {
			sessionId = cookie.Value
		}
	}

	if sessionId == "" {
		sc.logger.Warn("session not found in the request")
		sc.generateErrorResponse(c)
	}
	session, err := sc.getSessionData(sessionId)
	if err != nil {
		sc.logger.Warnf("error validating sessionId %s", sessionId)
		sc.generateErrorResponse(c)
	}
	c.JSON(200, session)
}

func (sc *SessionController) getSessionData(sessionId string) (session map[string]interface{}, err error) {
	session = make(map[string]interface{})
	sessionType := config.GetConfig().Session.Type

	if sessionType == "stateless" {
		publicKey := config.GetConfig().Session.Jwt.PublicKey
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(sessionId, claims, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			return session, err
		}
		session = claims
	} else {
		statefulSession, err := config.GetConfig().Session.DataStore.Repo.GetSession(sessionId)
		if statefulSession.GetUserID() == "" {
			return session, errors.New("User session  not found")
		}
		if err != nil {
			return session, err
		}
		session["id"] = statefulSession.ID
		session["created"] = statefulSession.CreatedAt
		session["properties"] = statefulSession.Properties
	}
	return session, err
}

func (sc *SessionController) generateErrorResponse(c *gin.Context) {
	c.JSON(404, gin.H{"valid": "false"})
}

func NewSessionController() *SessionController {
	conf := config.GetConfig()
	return &SessionController{
		logger: conf.Logger.WithField("module", "SessionController"),
	}
}
