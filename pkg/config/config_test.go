package config

import (
	"testing"

	"github.com/maximthomas/gortas/pkg/session"
	"github.com/spf13/viper"

	"github.com/stretchr/testify/assert"
)

func TestReadConfigFileViper(t *testing.T) {
	viper.SetConfigName("auth-config-dev") // name of config file (without extension)
	viper.AddConfigPath("../../test")      // optionally look for config in the working directory
	err := viper.ReadInConfig()            // Find and read the config file
	assert.NoError(t, err)
	err = InitConfig()
	assert.NoError(t, err)
	conf := GetConfig()
	assert.True(t, len(conf.Flows) > 0)
	assert.NotEmpty(t, config.Session.Jwt.PrivateKeyPem)
	assert.NotEmpty(t, session.GetSessionService().Jwt.PrivateKeyID)
	assert.NotNil(t, session.GetSessionService().Jwt.PublicKey)
	assert.NotNil(t, session.GetSessionService().Jwt.PrivateKey)
	assert.Equal(t, 1, len(conf.Server.Cors.AllowedOrigins))
}
