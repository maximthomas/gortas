package server

import (
	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/controller"
	cors "github.com/rs/cors/wrapper/gin"
)

func setupRouter(conf config.Config) *gin.Engine {
	router := gin.Default()

	c := cors.New(cors.Options{
		AllowedOrigins:   conf.Server.Cors.AllowedOrigins,
		AllowCredentials: true,
		Debug:            true,
	})

	router.Use(c)

	var loginController = controller.NewLoginController(conf)
	var idmController = controller.NewIDMController(conf)

	v1 := router.Group("/gortas/v1")
	{
		login := v1.Group("/login")
		{
			route := "/:realm/:chain"
			login.GET(route, func(context *gin.Context) {
				realmId := context.Param("realm")
				authChainId := context.Param("chain")
				loginController.Login(realmId, authChainId, context)
			})
			login.POST(route, func(context *gin.Context) {
				realmId := context.Param("realm")
				authChainId := context.Param("chain")
				loginController.Login(realmId, authChainId, context)
			})
		}
		idm := v1.Group("/idm")
		{
			idm.GET("", func(context *gin.Context) {
				idmController.Profile(context)
			})
		}

	}
	return router
}

func RunServer() {
	ac := config.GetConfig()
	router := setupRouter(ac)
	err := router.Run(":" + "8080")
	if err != nil {
		panic(err)
	}
}
