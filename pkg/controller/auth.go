package controller

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/log"
	"github.com/sirupsen/logrus"
)

// AuthController rest controller for authentication
type AuthController struct {
	logger logrus.FieldLogger
}

// Auth gin handler function
func (a *AuthController) Auth(c *gin.Context) {
	fn := c.Param("flow")

	var cbReq callbacks.Request
	var fID string
	if c.Request.Method == http.MethodPost {
		err := c.ShouldBindJSON(&cbReq)
		if err != nil {
			logrus.Errorf("error binding json body %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
			return
		}
		fID = cbReq.FlowID
		if fID == "" {
			fID, _ = c.Cookie(state.FlowCookieName)
		}
	}
	(&cbReq).FlowID = fID
	fp := auth.NewFlowProcessor()
	cbResp, err := fp.Process(fn, cbReq, c.Request, c.Writer)
	a.generateResponse(c, cbResp, err)
}

func (a *AuthController) generateResponse(c *gin.Context, cbResp callbacks.Response, err error) {
	if err != nil {
		logrus.Errorf("authentication error %v", err)
		deleteCookie(state.FlowCookieName, c)
		c.JSON(http.StatusUnauthorized, gin.H{"status": "fail"})
		return
	}

	if cbResp.Token != "" {
		setCookie(state.SessionCookieName, cbResp.Token, c)
		deleteCookie(state.FlowCookieName, c)
		c.JSON(http.StatusOK, cbResp)
	} else if cbResp.FlowID != "" {
		status := http.StatusOK
		outCb := make([]callbacks.Callback, 0)
		for _, cb := range cbResp.Callbacks {
			if cb.Type == callbacks.TypeHTTPStatus {
				status, err = strconv.Atoi(cb.Value)
				if err != nil {
					errMsg := fmt.Sprintf("error parsing status %v", cb.Value)
					a.logger.Errorf(errMsg)
					c.JSON(http.StatusInternalServerError, gin.H{"status": "fail", "message": errMsg})
					return
				}
				for k, val := range cb.Properties {
					c.Header(k, val)
				}
			} else {
				outCb = append(outCb, cb)
			}
		}
		cbOutResp := callbacks.Response{
			Callbacks: outCb,
			Module:    cbResp.Module,
			FlowID:    cbResp.FlowID,
		}
		setCookie(state.FlowCookieName, cbResp.FlowID, c)
		c.JSON(status, cbOutResp)
	} else {
		a.logger.Error("this should be never happen")
		c.JSON(http.StatusInternalServerError, gin.H{"status": "fail"})
	}
}

func setCookie(name, value string, c *gin.Context) {
	c.SetCookie(name, value, 0, "/", "", false, true)
}

func deleteCookie(name string, c *gin.Context) {
	c.SetCookie(name, "", -1, "/", "", false, true)
}

func NewAuthController() *AuthController {
	logger := log.WithField("module", "AuthController")
	return &AuthController{logger}
}
