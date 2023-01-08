package controller

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/log"
	"github.com/maximthomas/gortas/pkg/session"
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
		return
	}

	session, err := session.GetSessionService().GetSessionData(sessionId)
	if err != nil {
		sc.logger.Warnf("error validating sessionId %s", sessionId)
		sc.generateErrorResponse(c)
	}
	c.JSON(200, session)
}

func (sc *SessionController) SessionJwt(c *gin.Context) {
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
		return
	}
	jwt, err := session.GetSessionService().ConvertSessionToJwt(sessionId)
	if err != nil {
		sc.logger.Warnf("error validating sessionId %s", sessionId)
		sc.generateErrorResponse(c)
	}
	c.JSON(200, gin.H{"jwt": jwt})
}

func (sc *SessionController) generateErrorResponse(c *gin.Context) {
	c.JSON(404, gin.H{"error": "token not found"})
}

func NewSessionController() *SessionController {
	return &SessionController{
		logger: log.WithField("module", "SessionController"),
	}
}
