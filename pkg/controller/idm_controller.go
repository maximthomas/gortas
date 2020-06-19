package controller

import (
	"net/http"

	"github.com/dgrijalva/jwt-go"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/repo"
	"github.com/sirupsen/logrus"
)

type IDMController struct {
	sr     repo.SessionRepository
	logger logrus.FieldLogger
}

func NewIDMController(config config.Config) *IDMController {
	logger := config.Logger.WithField("module", "IDMController")
	sr := config.Session.DataStore.Repo
	return &IDMController{sr, logger}
}

func (ic IDMController) Profile(c *gin.Context) {
	sessID := getSessionIdFromRequest(c)
	if sessID == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
	} else {
		s, err := ic.sr.GetSession(sessID)
		if err != nil {
			token, err := jwt.Parse(sessID, func(token *jwt.Token) (interface{}, error) {
				return config.GetConfig().Session.Jwt.PublicKey, nil
			})
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
			}
			c.JSON(http.StatusOK, token)
		} else {
			c.JSON(http.StatusOK, s)
		}
	}
}
