package controller

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/sirupsen/logrus"
)

//AuthController rest controller for authentication
type AuthController struct {
	logger logrus.FieldLogger
}

// Auth gin handler function
func (a *AuthController) Auth(c *gin.Context) {
	fn := c.Param("flow")

	var cbReq callbacks.Request
	var fId string
	if c.Request.Method == http.MethodPost {
		err := c.ShouldBindJSON(&cbReq)
		if err != nil {
			logrus.Errorf("error binding json body %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
			return
		}
		fId = cbReq.FlowId
		if fId == "" {
			fId, _ = c.Cookie(state.FlowCookieName)
		}
	}

	f, err := auth.GetFlow(fn, fId)
	if err != nil {
		logrus.Errorf("error getting flow %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": err.Error()})
		return
	}

	cbResp, err := f.Process(cbReq, c.Request, c.Writer)
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
	} else if cbResp.FlowId != "" {
		status := http.StatusOK
		outCb := make([]callbacks.Callback, 0)
		for _, cb := range cbResp.Callbacks {
			if cb.Type == callbacks.TypeHttpStatus {
				status, err = strconv.Atoi(cb.Value)
				if err != nil {
					errMsg := fmt.Sprintf("error parsing status %v", cb.Value)
					a.logger.Errorf(errMsg)
					c.JSON(500, gin.H{"status": "fail", "message": errMsg})
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
			FlowId:    cbResp.FlowId,
		}
		setCookie(state.FlowCookieName, cbResp.FlowId, c)
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
	conf := config.GetConfig()
	logger := conf.Logger.WithField("module", "AuthController")
	return &AuthController{logger}
}
