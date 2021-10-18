package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/mitchellh/mapstructure"

	"github.com/google/uuid"

	"github.com/maximthomas/gortas/pkg/repo"
	"github.com/spf13/viper"

	"github.com/sirupsen/logrus"
)

type Config struct {
	Authentication Authentication
	Logger         *logrus.Logger
	Session        Session `yaml:"session"`
	Server         Server  `yaml:"server"`
	EncryptionKey  string  `yaml:"encryptionKey"`
}

type Authentication struct {
	Realms map[string]Realm `yaml:"realms"`
}

type Realm struct {
	ID            string
	Modules       map[string]Module   `yaml:"modules"`
	AuthFlows     map[string]AuthFlow `yaml:"authFlows"`
	UserDataStore UserDataStore       `yaml:"userDataStore"`
}

type AuthFlow struct {
	Modules []FlowModule `yaml:"modules"`
}

type UserDataStore struct {
	Type       string                 `yaml:"type"`
	Properties map[string]interface{} `yaml:"properties,omitempty"`
	Repo       repo.UserRepository
}

type Module struct {
	Type       string                 `yaml:"type"`
	Properties map[string]interface{} `yaml:"properties,omitempty"`
}

type FlowModule struct {
	ID         string                 `yaml:"id"`
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
	Repo       repo.SessionRepository
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
	auth := &config.Authentication

	config.Logger = logger
	if err != nil { // Handle errors reading the config file
		configLogger.Errorf("Fatal error config file: %s \n", err)
		panic(err)
	}
	for id, realm := range auth.Realms {
		realm.ID = id
		if realm.UserDataStore.Type == "ldap" {
			prop := realm.UserDataStore.Properties
			ur := &repo.UserLdapRepository{}
			err := mapstructure.Decode(prop, ur)
			if err != nil {
				configLogger.Fatal(err)
				return err
			}
			realm.UserDataStore.Repo = ur
		} else if realm.UserDataStore.Type == "mongodb" {
			prop := realm.UserDataStore.Properties
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
			realm.UserDataStore.Repo = ur
		} else {
			realm.UserDataStore.Repo = repo.NewInMemoryUserRepository()
		}
		auth.Realms[id] = realm
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
		config.Session.DataStore.Repo, err = repo.NewMongoSessionRepository(url, db, col)
		if err != nil {
			configLogger.Fatal(err)
			return err
		}
	} else {
		config.Session.DataStore.Repo = repo.NewInMemorySessionRepository(logger)
	}

	configLogger.Infof("got configuration %+v", auth)

	return nil
}

func GetConfig() Config {
	return config
}

func SetConfig(newConfig Config) {
	config = newConfig
}
