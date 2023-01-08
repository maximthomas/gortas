// Package plugindemo a demo plugin.
package gortas_traefik_plugin

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
)

// Config the plugin configuration.
type Config struct {
	GortasUrl string `yaml:"gortasUrl,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{GortasUrl: ""}
}

// GortasPlugin a GortasPlugin plugin.
type GortasPlugin struct {
	gortasUrl string
	name      string
	tr        *http.Transport
	next      http.Handler
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	log.Printf("got configuration %v", config)

	return &GortasPlugin{
		gortasUrl: config.GortasUrl + "/v1/session/jwt",
		next:      next,
		name:      name,
		tr: &http.Transport{
			MaxIdleConns:       10,
			IdleConnTimeout:    10 * time.Second,
			DisableCompression: true,
		},
	}, nil
}

func (a *GortasPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	bearerToken := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	if bearerToken == "" {
		a.next.ServeHTTP(rw, req)
		return
	}

	jwt, err := a.convertToken(bearerToken)
	if err != nil {
		log.Printf("error converting token: %v", err)
	} else {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	a.next.ServeHTTP(rw, req)
}

func (a *GortasPlugin) convertToken(token string) (jwt string, err error) {
	client := &http.Client{Transport: a.tr}
	req, err := http.NewRequest("GET", a.gortasUrl, nil)

	req.Header.Add("Authorization", "Bearer "+token)
	resp, err := client.Do(req)

	if err != nil {
		log.Print(err)
		return jwt, err
	}

	defer resp.Body.Close()

	jwtReponse := &struct {
		Jwt   string
		Error string
	}{}

	err = json.NewDecoder(resp.Body).Decode(jwtReponse)
	if err != nil {
		log.Print(err)
		return jwt, err
	}

	if jwtReponse.Error != "" {
		return jwt, errors.New(jwtReponse.Error)
	}

	return jwtReponse.Jwt, err
}
