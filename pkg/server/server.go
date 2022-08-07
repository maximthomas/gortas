package server

import (
	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/controller"
	"github.com/maximthomas/gortas/pkg/middleware"
	cors "github.com/rs/cors/wrapper/gin"
)

func SetupRouter(conf config.Config) *gin.Engine {
	router := gin.Default()
	c := cors.New(cors.Options{
		AllowedOrigins:   conf.Server.Cors.AllowedOrigins,
		AllowCredentials: true,
		Debug:            gin.IsDebugging(),
	})

	ru := middleware.NewRequestURIMiddleware()

	router.Use(c, ru)
	var ac = controller.NewAuthController()
	var sc = controller.NewSessionController()

	v1 := router.Group("/gortas/v1")
	{
		auth := v1.Group("/auth")
		{
			route := "/:flow"
			auth.GET(route, ac.Auth)
			auth.POST(route, ac.Auth)
		}
		session := v1.Group("/session")
		{
			session.GET("", sc.SessionInfo)
		}
	}
	return router
}

func RunServer() {
	ac := config.GetConfig()
	router := SetupRouter(ac)
	err := router.Run(":" + "8080")
	if err != nil {
		panic(err)
	}
}
