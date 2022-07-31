package cmd

import (
	"testing"

	"github.com/maximthomas/gortas/pkg/config"

	"github.com/stretchr/testify/assert"
)

func TestExecute(t *testing.T) {
	args := []string{"version", "--config", "../test/auth-config-dev.yaml"}
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	assert.NoError(t, err)
	conf := config.GetConfig()
	assert.True(t, len(conf.Authentication.AuthFlows) > 0)

}
