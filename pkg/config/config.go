package config

import (
	"github.com/maximthomas/gortas/pkg/session"
	"github.com/maximthomas/gortas/pkg/user"
	"github.com/spf13/viper"

	"github.com/sirupsen/logrus"
)

type Config struct {
	Logger        *logrus.Logger
	Flows         map[string]Flow       `yaml:"flows"`
	Session       session.SessionConfig `yaml:"session"`
	Server        Server                `yaml:"server"`
	EncryptionKey string                `yaml:"encryptionKey"`
	UserDataStore user.UserConfig       `yaml:"userDataStore"`
}

type Flow struct {
	Modules []Module `yaml:"modules"`
}

type Module struct {
	ID         string                 `yaml:"id"`
	Type       string                 `yaml:"type"`
	Properties map[string]interface{} `yaml:"properties,omitempty"`
	Criteria   string                 `yaml:"criteria"`
}

type Server struct {
	Cors Cors
}

type Cors struct {
	AllowedOrigins []string
}

var config Config

func InitConfig() error {
	logger := logrus.New()
	//newLogger.SetFormatter(&logrus.JSONFormatter{})
	//newLogger.SetReportCaller(true)
	var configLogger = logger.WithField("module", "config")

	err := viper.Unmarshal(&config)

	config.Logger = logger
	if err != nil { // Handle errors reading the config file
		configLogger.Errorf("Fatal error config file: %s \n", err)
		panic(err)
	}
	err = user.InitUserService(config.UserDataStore)
	if err != nil {
		configLogger.Errorf("Fatal error config file: %s \n", err)
		panic(err)
	}
	session.InitSessionService(config.Session)

	configLogger.Infof("got configuration %+v\n", config)

	return nil
}

func GetConfig() Config {
	return config
}

func SetConfig(newConfig Config) {
	config = newConfig
	user.InitUserService(newConfig.UserDataStore)
	session.InitSessionService(newConfig.Session)
}
