package integration_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/repo"
	"github.com/maximthomas/gortas/pkg/server"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var privateKey, _ = rsa.GenerateKey(rand.Reader, 1024)
var publicKey = &privateKey.PublicKey
var ur = repo.NewInMemoryUserRepository()
var (
	authConf = config.Authentication{
		Realms: map[string]config.Realm{
			"users": {
				ID: "users",
				Modules: map[string]config.Module{
					"otp": {
						Type: "otp",
						Properties: map[string]interface{}{
							"otpLength":          4,
							"useLetters":         false,
							"useDigits":          true,
							"otpTimeoutSec":      180,
							"otpResendSec":       90,
							"otpRetryCount":      5,
							"OtpMessageTemplate": "Code {{.OTP}} valid for {{.ValidFor}} min",
							"sender": map[string]interface{}{
								"senderType": "test",
								"properties": map[string]interface{}{
									"host": "localhost",
									"port": 1234,
								},
							},
						}},
					"phone": {
						Type: "credentials",
						Properties: map[string]interface{}{
							"primaryField": map[string]interface{}{
								"Name":       "phone",
								"Prompt":     "Phone",
								"Required":   true,
								"Validation": "^\\d{4,20}$",
							},
						}},
				},
				AuthFlows: map[string]config.AuthFlow{
					"otp": {Modules: []config.FlowModule{
						{
							ID: "phone",
						},
						{
							ID: "otp",
						},
					}},
				},
				UserDataStore: config.UserDataStore{
					Repo: ur,
				},
			},
		},
	}
	logger = logrus.New()
	conf   = config.Config{
		Authentication: authConf,
		Logger:         logger,
		Session: config.Session{
			Type:    "stateless",
			Expires: 60000,
			Jwt: config.SessionJWT{
				Issuer:       "http://gortas",
				PrivateKey:   privateKey,
				PublicKey:    publicKey,
				PrivateKeyID: "dummy",
			},
			DataStore: config.SessionDataStore{Repo: repo.NewInMemorySessionRepository(logger)},
		},
	}
	router *gin.Engine
)

func init() {
	config.SetConfig(conf)
	router = server.SetupRouter(conf)
}
func TestOTPAuth(t *testing.T) {

	const authUrl = "http://localhost/gortas/v1/auth/users/otp"

	const badPhone = "123"
	const validPhone = "5551112233"

	//init auth
	assert.Equal(t, 2, len(router.Routes()))
	request := httptest.NewRequest("GET", authUrl, nil)
	cbReq := &callbacks.Request{}
	resp := executeRequest(t, request, cbReq)
	assert.Equal(t, "phone", cbReq.Module)
	assert.Equal(t, 1, len(cbReq.Callbacks))
	assert.Equal(t, "phone", cbReq.Callbacks[0].Name)

	cookieVal, _ := GetCookieValue(state.FlowCookieName, resp.Cookies())

	flowCookie := &http.Cookie{
		Name:  state.FlowCookieName,
		Value: cookieVal,
	}

	//send invalid phone
	requestBody := fmt.Sprintf(`{"callbacks":[{"name":"phone", "value": "%v"}]}`, badPhone)

	request = httptest.NewRequest("POST", authUrl, bytes.NewBuffer([]byte(requestBody)))
	request.AddCookie(flowCookie)
	cbReq = &callbacks.Request{}
	executeRequest(t, request, cbReq)
	assert.Equal(t, "phone", cbReq.Module)
	assert.Equal(t, 1, len(cbReq.Callbacks))
	assert.Equal(t, "phone", cbReq.Callbacks[0].Name)
	assert.Equal(t, "Phone invalid", cbReq.Callbacks[0].Error)

	//send valid phone
	requestBody = fmt.Sprintf(`{"callbacks":[{"name":"phone", "value": "%v"}]}`, validPhone)
	request = httptest.NewRequest("POST", authUrl, bytes.NewBuffer([]byte(requestBody)))
	request.AddCookie(flowCookie)

	cbReq = &callbacks.Request{}
	executeRequest(t, request, cbReq)
	assert.Equal(t, "otp", cbReq.Module)
	assert.Equal(t, 2, len(cbReq.Callbacks))
	assert.Equal(t, "otp", cbReq.Callbacks[0].Name)
	assert.Equal(t, "action", cbReq.Callbacks[1].Name)

	//send invalid OTP
	requestBody = fmt.Sprintf(`{"callbacks":[{"name":"otp", "value": "%v"},{"name":"action", "value": "%v"}]}`, "1234", "check")
	request = httptest.NewRequest("POST", authUrl, bytes.NewBuffer([]byte(requestBody)))
	request.AddCookie(flowCookie)
	cbReq = &callbacks.Request{}
	executeRequest(t, request, cbReq)

	//send valid OTP
	session, _ := config.GetConfig().Session.DataStore.Repo.GetSession(cookieVal)
	var fs state.FlowState
	json.Unmarshal([]byte(session.Properties["fs"]), &fs)
	fs.Modules[1].State["otp"] = "1234"
	sd, _ := json.Marshal(fs)
	session.Properties["fs"] = string(sd)
	config.GetConfig().Session.DataStore.Repo.UpdateSession(session)

	requestBody = fmt.Sprintf(`{"callbacks":[{"name":"otp", "value": "%v"},{"name":"action", "value": "%v"}]}`, "1234", "check")
	request = httptest.NewRequest("POST", authUrl, bytes.NewBuffer([]byte(requestBody)))
	request.AddCookie(flowCookie)
	cbReq = &callbacks.Request{}
	resp = executeRequest(t, request, cbReq)
	cookie, err := GetCookieValue("GortasSession", resp.Cookies())
	assert.NotEmpty(t, cookie)
	assert.NoError(t, err)
}

func executeRequest(t *testing.T, r *http.Request, res interface{}) *http.Response {
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, r)
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	reponse := recorder.Body.String()
	err := json.Unmarshal([]byte(reponse), res)
	assert.NoError(t, err)
	return recorder.Result()
}
