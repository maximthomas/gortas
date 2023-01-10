package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/server"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "gortas",
		Short: "Gortas is a golang authentication service",
		Run: func(cmd *cobra.Command, args []string) {
			server.RunServer()
		},
	}

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Shown version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("0.0.1")
		},
	}
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/auth-config.yaml)")
	rootCmd.AddCommand(versionCmd)
}

func er(msg interface{}) {
	fmt.Println("Error:", msg)
	os.Exit(1)
}

func initConfig() {
	fmt.Println(os.Getwd())
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			er(err)
		}

		// Search config in home directory with name ".cobra" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName("auth-config")
	}

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
		err = config.InitConfig()
		if err != nil {
			er(err)
		}
	} else {
		er(err)
	}
}
