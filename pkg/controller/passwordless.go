package controller

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/maximthomas/gortas/pkg/auth/constants"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/middleware"
	"github.com/maximthomas/gortas/pkg/session"
	"github.com/maximthomas/gortas/pkg/user"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/sirupsen/logrus"
	"github.com/skip2/go-qrcode"
)

// TODO v2 refactor passwordless architecture
type PasswordlessServicesController struct {
	sr     session.SessionRepository
	logger logrus.FieldLogger
	conf   config.Config
}

func NewPasswordlessServicesController(config config.Config) *PasswordlessServicesController {
	logger := config.Logger.WithField("module", "PasswordlessServicesController")
	sr := config.Session.DataStore.Repo

	return &PasswordlessServicesController{sr, logger, config}
}

type QRProps struct {
	Secret string `json:"secret"`
}

func (pc PasswordlessServicesController) RegisterGenerateQR(c *gin.Context) {
	si, ok := c.Get("session")
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	s := si.(session.Session)
	uid := s.GetUserID()
	ur := user.GetUserService().Repo

	_, ok = ur.GetUser(uid)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "No user found in the repository"})
		return
	}
	requestURI := middleware.GetRequestURI(c)
	imageData := fmt.Sprintf("%s?sid=%s&action=register", requestURI, s.ID)
	png, err := qrcode.Encode(imageData, qrcode.Medium, 256)
	if err != nil {
		pc.logger.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "error generate QR code"})
		return
	}

	image := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(png))
	c.JSON(http.StatusOK, gin.H{"qr": image})
}

func (pc PasswordlessServicesController) RegisterConfirmQR(c *gin.Context) {
	si, ok := c.Get("session")
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	s := si.(session.Session)
	uid := s.GetUserID()
	ur := user.GetUserService().Repo

	user, ok := ur.GetUser(uid)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "No user found in the repository"})
		return
	}
	//generate secret key
	secret := uuid.New().String()
	qrProps := QRProps{Secret: secret}
	qrPropsJSON, err := json.Marshal(qrProps)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "error updating user"})
		return
	}
	if user.Properties == nil {
		user.Properties = make(map[string]string)
	}
	user.Properties["passwordless.qr"] = string(qrPropsJSON)
	err = ur.UpdateUser(user)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "error updating user"})
		return
	}
	requestURI := middleware.GetRequestURI(c)
	authURI := strings.ReplaceAll(requestURI, "/idm/otp/qr", "/service/otp/qr/login")

	c.JSON(http.StatusOK, gin.H{"secret": secret, "userId": user.ID, "authURI": authURI})
}

func (pc PasswordlessServicesController) AuthQR(c *gin.Context) {
	var authQRRequest struct {
		SID    string `json:"sid"`
		UID    string `json:"uid"`
		Realm  string `json:"realm"`
		Secret string `json:"secret"`
	}

	err := c.ShouldBindJSON(&authQRRequest)
	if err != nil {
		pc.logger.Warn("invalid request body", err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	session, err := pc.sr.GetSession(authQRRequest.SID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "there is no valid authentication session"})
		return
	}

	ur := user.GetUserService().Repo
	user, ok := ur.GetUser(authQRRequest.UID)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "error updating user"})
		return
	}
	jsonProp, ok := user.Properties["passwordless.qr"]
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "the user is not bound to QR"})
		return
	}
	var qrProps QRProps
	err = json.Unmarshal([]byte(jsonProp), &qrProps)
	if err != nil {
		pc.logger.Warn("AuthQR: the user is not bound to QR")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "the user is not bound to QR"})
		return
	}

	err = json.Unmarshal([]byte(jsonProp), &qrProps)
	if qrProps.Secret != authQRRequest.Secret {
		pc.logger.Warn("AuthQR: user qr secrets does not match")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "the user is not bound to QR"})
		return
	}

	//authorise session
	var fs state.FlowState
	err = json.Unmarshal([]byte(session.Properties[constants.FlowStateSessionProperty]), &fs)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "there is no valid authentication session"})
		return
	}

	moduleFound := false
	for _, m := range fs.Modules {
		if m.Type == "qr" && m.Status == state.IN_PROGRESS {
			m.State["qrUserId"] = authQRRequest.UID
			moduleFound = true
			break
		}
	}
	if !moduleFound {
		pc.logger.Warn("AuthQR: no active qr module in the chain")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "there is no valid authentication session"})
		return
	}
	fsJSON, err := json.Marshal(fs)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "there is no valid authentication session"})
		return
	}
	session.Properties[constants.FlowStateSessionProperty] = string(fsJSON)
	err = pc.sr.UpdateSession(session)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})

}
