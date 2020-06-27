package server

import (
	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/controller"
	"github.com/maximthomas/gortas/pkg/middleware"
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
	var pwlessCtrl = controller.NewPasswordlessServicesController(conf)

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
		am := middleware.NewAuthenticatedMiddleware(conf.Session)
		idm.Use(am)
		{
			idm.GET("", idmController.Profile)
			otpQR := idm.Group("/otp/qr")
			{
				otpQR.GET("/", pwlessCtrl.RegisterGenerateQR)
				otpQR.POST("/", pwlessCtrl.RegisterConfirmQR)
			}
		}
		service := v1.Group("/service")
		{
			otpQrLogin := service.Group("/otp/qr/login")
			otpQrLogin.POST("/", pwlessCtrl.AuthQR)
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
