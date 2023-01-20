package controller

import (
	"net/http"
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
	var sessionID string
	authHeader := c.Request.Header.Get("Authorization")
	if authHeader != "" { // from header
		sessionID = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if sessionID == "" { // from cookie
		cookie, err := c.Request.Cookie(state.SessionCookieName)
		if err == nil {
			sessionID = cookie.Value
		}
	}

	if sessionID == "" {
		sc.logger.Warn("session not found in the request")
		sc.generateErrorResponse(c)
		return
	}

	sess, err := session.GetSessionService().GetSessionData(sessionID)
	if err != nil {
		sc.logger.Warnf("error validating sessionId %s", sessionID)
		sc.generateErrorResponse(c)
	}
	c.JSON(http.StatusOK, sess)
}

func (sc *SessionController) SessionJwt(c *gin.Context) {
	var sessionID string
	authHeader := c.Request.Header.Get("Authorization")
	if authHeader != "" { // from header
		sessionID = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if sessionID == "" { // from cookie
		cookie, err := c.Request.Cookie(state.SessionCookieName)
		if err == nil {
			sessionID = cookie.Value
		}
	}

	if sessionID == "" {
		sc.logger.Warn("session not found in the request")
		sc.generateErrorResponse(c)
		return
	}
	jwt, err := session.GetSessionService().ConvertSessionToJwt(sessionID)
	if err != nil {
		sc.logger.Warnf("error validating sessionId %s", sessionID)
		sc.generateErrorResponse(c)
	}
	c.JSON(http.StatusOK, gin.H{"jwt": jwt})
}

func (sc *SessionController) generateErrorResponse(c *gin.Context) {
	c.JSON(http.StatusNotFound, gin.H{"error": "token not found"})
}

func NewSessionController() *SessionController {
	return &SessionController{
		logger: log.WithField("module", "SessionController"),
	}
}
