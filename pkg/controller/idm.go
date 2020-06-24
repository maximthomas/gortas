package controller

import (
	"github.com/maximthomas/gortas/pkg/models"
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
	conf   config.Config
}

func NewIDMController(config config.Config) *IDMController {
	logger := config.Logger.WithField("module", "IDMController")
	sr := config.Session.DataStore.Repo
	return &IDMController{sr, logger, config}
}

func (ic IDMController) Profile(c *gin.Context) {

	si, ok := c.Get("session")
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	s := si.(models.Session)

	if s.ID == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
	} else {
		s, err := ic.sr.GetSession(s.ID)
		if err != nil {
			token, err := jwt.Parse(s.ID, func(token *jwt.Token) (interface{}, error) {
				return ic.conf.Session.Jwt.PublicKey, nil
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
