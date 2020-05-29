package config

import (
	"testing"

	"github.com/spf13/viper"

	"github.com/stretchr/testify/assert"
)

func TestReadConfigFileViper(t *testing.T) {
	viper.SetConfigName("auth-config") // name of config file (without extension)
	viper.AddConfigPath("../..")       // optionally look for config in the working directory
	err := viper.ReadInConfig()        // Find and read the config file
	assert.NoError(t, err)
	err = InitConfig()
	assert.NoError(t, err)
	conf := GetConfig()
	assert.NotNil(t, conf.Authentication)
	r := conf.Authentication.Realms["staff"]
	assert.True(t, len(r.AuthChains) > 0)
	assert.Equal(t, "staff", r.ID)
	assert.NotEmpty(t, config.Session.Jwt.PrivateKeyPem)
	assert.NotEmpty(t, config.Session.Jwt.PrivateKeyID)
	assert.NotNil(t, config.Session.Jwt.PublicKey)
	assert.NotNil(t, config.Session.Jwt.PrivateKey)
	assert.Equal(t, 1, len(conf.Server.Cors.AllowedOrigins))
}
