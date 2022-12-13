package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/session"
)

func NewAuthenticatedMiddleware(s config.Session) gin.HandlerFunc {
	return authenticatedMiddleware{s}.build()
}

type authenticatedMiddleware struct {
	sc config.Session
}

func (a authenticatedMiddleware) build() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := getSessionIDFromRequest(c)
		if sessionID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
			return
		}
		var sess session.Session
		var err error
		if a.sc.Type == "stateless" {
			claims := jwt.MapClaims{}
			_, err := jwt.ParseWithClaims(sessionID, claims, func(token *jwt.Token) (interface{}, error) {
				return a.sc.Jwt.PublicKey, nil
			})
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
				return
			}
			if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
				return
			}

			sessionProps := make(map[string]string)
			for key, value := range claims {
				if value == nil {
					continue
				}
				var strVal string
				if key == "props" {
					bytes, err := json.Marshal(value)
					if err != nil {
						c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Error parsing token attrs"})
						return
					}
					strVal = string(bytes)
				} else {
					strVal = fmt.Sprintf("%v", value)
				}
				sessionProps[key] = strVal
			}

			sess = session.Session{
				ID:         sessionID,
				Properties: sessionProps,
			}
		} else {
			sess, err = a.sc.DataStore.Repo.GetSession(sessionID)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
				return
			}
		}
		uid := sess.GetUserID()
		if uid == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Session is not valid"})
			return
		}

		c.Set("session", sess)

		c.Next()
	}
}

func getSessionIDFromRequest(c *gin.Context) string {
	sessionCookie, err := c.Request.Cookie(state.SessionCookieName)
	if err == nil {
		return sessionCookie.Value
	}
	reqToken := c.Request.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer ")
	if len(splitToken) == 2 {
		return splitToken[1]
	}

	return ""
}
