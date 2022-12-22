package controller

import (
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/session"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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

func (sc *SessionController) getSessionData(sessionId string) (sess map[string]interface{}, err error) {
	sess = make(map[string]interface{})
	sessionType := config.GetConfig().Session.Type

	if sessionType == "stateless" {
		publicKey := session.GetSessionService().Jwt.PublicKey
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(sessionId, claims, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			return sess, err
		}
		sess = claims
	} else {
		statefulSession, err := session.GetSessionService().GetSession(sessionId)
		if statefulSession.GetUserID() == "" {
			return sess, errors.New("User session  not found")
		}
		if err != nil {
			return sess, err
		}
		sess["id"] = statefulSession.ID
		sess["created"] = statefulSession.CreatedAt
		sess["properties"] = statefulSession.Properties
	}
	return sess, err
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
