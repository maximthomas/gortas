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
		Debug:            true,
	})

	ru := middleware.NewRequestURIMiddleware()

	router.Use(c, ru)
	var authController = controller.NewAuthController()

	v1 := router.Group("/gortas/v1")
	{
		auth := v1.Group("/auth")
		{
			route := "/:realm/:flow"
			auth.GET(route, authController.Auth)
			auth.POST(route, authController.Auth)
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
