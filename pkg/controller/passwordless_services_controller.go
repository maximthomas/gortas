package controller

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/models"
	"github.com/maximthomas/gortas/pkg/repo"
	"github.com/sirupsen/logrus"
	"github.com/skip2/go-qrcode"
)

type PasswordlessServicesController struct {
	sr     repo.SessionRepository
	logger logrus.FieldLogger
}

func NewPasswordlessServicesController(config config.Config) *PasswordlessServicesController {
	logger := config.Logger.WithField("module", "PasswordlessServicesController")
	sr := config.Session.DataStore.Repo
	return &PasswordlessServicesController{sr, logger}
}

func (pc PasswordlessServicesController) RegisterGenerateQR(c *gin.Context) {
	si, ok := c.Keys["session"]
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	s := si.(models.Session)
	uid := s.GetUserID()
	realm := s.GetRealm()
	ur := config.GetConfig().Authentication.Realms[realm].UserDataStore.Repo

	_, ok = ur.GetUser(uid)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "No user found in the repository"})
		return
	}

	imageData := fmt.Sprintf("%s?sid=%s&action=register", c.Request.RequestURI, s)
	png, err := qrcode.Encode(imageData, qrcode.Medium, 256)
	if err != nil {
		pc.logger.Error(err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "error generate QR code"})
		return
	}

	image := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(png))
	c.JSON(http.StatusOK, gin.H{"qr": image})
}

func (pc PasswordlessServicesController) RegisterConfirmQR(c *gin.Context) {
	si, ok := c.Keys["session"]
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	s := si.(models.Session)
	uid := s.GetUserID()
	realm := s.GetRealm()
	ur := config.GetConfig().Authentication.Realms[realm].UserDataStore.Repo

	user, ok := ur.GetUser(uid)
	if !ok {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "No user found in the repository"})
		return
	}
	//generate secret key
	secret := uuid.New().String()
	qrProps, err := json.Marshal("") //TODO implement
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "error updating user"})
		return
	}
	user.Properties["passwordless.qr"] = string(qrProps)
	ur.UpdateUser(user)
	c.JSON(http.StatusOK, gin.H{"secret": secret, "uid": user.ID})
}

func (pc PasswordlessServicesController) AuthQR(c *gin.Context) {
	var authQRRequest struct {
		SID    string `json:"sid"`
		UID    string `json:"uid"`
		Realm  string `json:"realm"`
		Secret string `json:"secret"`
	}

	err := c.ShouldBindJSON(authQRRequest)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "error updating user"})
		return
	}

	session, err := pc.sr.GetSession(authQRRequest.SID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "there is no valid authentication session"})
		return
	}

	ur := config.GetConfig().Authentication.Realms[authQRRequest.Realm].UserDataStore.Repo
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
	props := make(map[string]string)
	err = json.Unmarshal([]byte(jsonProp), props)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "the user is not bound to QR"})
		return
	}

	//authorise session
	var lss auth.LoginSessionState
	err = json.Unmarshal([]byte(session.Properties["lss"]), &lss)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "there is no valid authentication session"})
		return
	}
	lss.SharedState["qrUserId"] = authQRRequest.UID
	lssJSON, err := json.Marshal(lss)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "there is no valid authentication session"})
		return
	}
	session.Properties["lss"] = string(lssJSON)
	err = pc.sr.UpdateSession(session)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": "success"})

}
