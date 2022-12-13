package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/mitchellh/mapstructure"

	"github.com/google/uuid"

	"github.com/maximthomas/gortas/pkg/repo"
	"github.com/maximthomas/gortas/pkg/session"
	"github.com/spf13/viper"

	"github.com/sirupsen/logrus"
)

type Config struct {
	Logger        *logrus.Logger
	Flows         map[string]Flow `yaml:"flows"`
	Session       Session         `yaml:"session"`
	Server        Server          `yaml:"server"`
	EncryptionKey string          `yaml:"encryptionKey"`
	UserDataStore UserDataStore   `yaml:"userDataStore"`
}

type Flow struct {
	Modules []Module `yaml:"modules"`
}

type UserDataStore struct {
	Type       string                 `yaml:"type"`
	Properties map[string]interface{} `yaml:"properties,omitempty"`
	Repo       repo.UserRepository
}

type Module struct {
	ID         string                 `yaml:"id"`
	Type       string                 `yaml:"type"`
	Properties map[string]interface{} `yaml:"properties,omitempty"`
	Criteria   string                 `yaml:"criteria"`
}

type Session struct {
	Type      string           `yaml:"type"`
	Expires   int              `yaml:"expires"`
	Jwt       SessionJWT       `yaml:"jwt,omitempty"`
	DataStore SessionDataStore `yaml:"dataStore,omitempty"`
}

type SessionJWT struct {
	Issuer        string `yaml:"issuer"`
	PrivateKeyPem string `yml:"privateKeyPem"`
	PrivateKeyID  string
	PrivateKey    *rsa.PrivateKey
	PublicKey     *rsa.PublicKey
}

type SessionDataStore struct {
	Repo       session.SessionRepository
	Type       string
	Properties map[string]string
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

	if config.UserDataStore.Type == "ldap" {
		prop := config.UserDataStore.Properties
		ur := &repo.UserLdapRepository{}
		err := mapstructure.Decode(prop, ur)
		if err != nil {
			configLogger.Fatal(err)
			return err
		}
		config.UserDataStore.Repo = ur
	} else if config.UserDataStore.Type == "mongodb" {
		prop := config.UserDataStore.Properties
		params := make(map[string]interface{})
		err := mapstructure.Decode(&prop, &params)
		if err != nil {
			configLogger.Fatal(err)
			return err
		}
		url, _ := params["url"].(string)
		db, _ := params["database"].(string)
		col, _ := params["collection"].(string)
		ur, err := repo.NewUserMongoRepository(url, db, col)
		if err != nil {
			panic(err)
		}
		config.UserDataStore.Repo = ur
	} else {
		config.UserDataStore.Repo = repo.NewInMemoryUserRepository()
	}

	if config.Session.Type == "stateless" {
		jwt := &config.Session.Jwt
		privateKeyBlock, _ := pem.Decode([]byte(jwt.PrivateKeyPem))
		privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
		if err != nil {
			configLogger.Fatal(err)
			return err
		}
		jwt.PrivateKey = privateKey
		jwt.PublicKey = &privateKey.PublicKey
		jwt.PrivateKeyID = uuid.New().String()
	}

	if config.Session.DataStore.Type == "mongo" {
		prop := config.Session.DataStore.Properties
		params := make(map[string]string)
		err := mapstructure.Decode(&prop, &params)
		if err != nil {
			configLogger.Fatal(err)
			return err
		}
		url, _ := params["url"]
		db, _ := params["database"]
		col, _ := params["collection"]
		config.Session.DataStore.Repo, err = session.NewMongoSessionRepository(url, db, col)
		if err != nil {
			configLogger.Fatal(err)
			return err
		}
	} else {
		config.Session.DataStore.Repo = session.NewInMemorySessionRepository(logger)
	}

	configLogger.Infof("got configuration %+v\n", config)

	return nil
}

func GetConfig() Config {
	return config
}

func SetConfig(newConfig Config) {
	config = newConfig
}
