package integration_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/constants"
	"github.com/maximthomas/gortas/pkg/auth/modules/otp"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/server"
	"github.com/maximthomas/gortas/pkg/session"
	"github.com/maximthomas/gortas/pkg/user"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var privateKey, _ = rsa.GenerateKey(rand.Reader, 1024)
var publicKey = &privateKey.PublicKey
var ur = user.NewInMemoryUserRepository()
var (
	flows = map[string]config.Flow{
		"otp": {Modules: []config.Module{
			{
				ID:       "otp_link",
				Type:     "otp",
				Criteria: constants.CriteriaSufficient,
				Properties: map[string]interface{}{
					"otpCheckMagicLink":  true,
					"otpLength":          4,
					"useLetters":         false,
					"useDigits":          true,
					"otpTimeoutSec":      180,
					"otpResendSec":       90,
					"otpRetryCount":      5,
					"OtpMessageTemplate": "Code {{.OTP}} valid for {{.ValidFor}} min, link code {{.MagicLink}}",
					"sender": map[string]interface{}{
						"senderType": "test",
						"properties": map[string]interface{}{
							"host": "localhost",
							"port": 1234,
						},
					},
				}},
			{
				ID:   "phone",
				Type: "credentials",
				Properties: map[string]interface{}{
					"primaryField": map[string]interface{}{
						"Name":       "phone",
						"Prompt":     "Phone",
						"Required":   true,
						"Validation": "^\\d{4,20}$",
					},
				},
			},
			{
				ID:   "otp",
				Type: "otp",
				Properties: map[string]interface{}{
					"otpLength":          4,
					"useLetters":         false,
					"useDigits":          true,
					"otpTimeoutSec":      180,
					"otpResendSec":       90,
					"otpRetryCount":      5,
					"OtpMessageTemplate": "Code {{.OTP}} valid for {{.ValidFor}} min, link code {{.MagicLink}}",
					"sender": map[string]interface{}{
						"senderType": "test",
						"properties": map[string]interface{}{
							"host": "localhost",
							"port": 1234,
						},
					},
				},
			},
		}},
	}

	logger = logrus.New()
	conf   = config.Config{
		Flows:  flows,
		Logger: logger,
		Session: config.Session{
			Type:    "stateless",
			Expires: 60000,
			Jwt: config.SessionJWT{
				Issuer:       "http://gortas",
				PrivateKey:   privateKey,
				PublicKey:    publicKey,
				PrivateKeyID: "dummy",
			},
			DataStore: config.SessionDataStore{Repo: session.NewInMemorySessionRepository(logger)},
		},
		EncryptionKey: "Gb8l9wSZzEjeL2FTRG0k6bBnw7AZ/rBCcZfDDGLVreY=",
	}
	router *gin.Engine
)

func init() {
	config.SetConfig(conf)
	router = server.SetupRouter(conf)
}
func TestOTPAuth(t *testing.T) {

	const authUrl = "http://localhost/gortas/v1/auth/otp"

	const badPhone = "123"
	const validPhone = "5551112233"

	//init auth
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
	err := json.Unmarshal([]byte(session.Properties[constants.FlowStateSessionProperty]), &fs)
	if err != nil {
		panic(err)
	}
	fs.Modules[2].State["otp"] = "1234"
	sd, _ := json.Marshal(fs)
	session.Properties[constants.FlowStateSessionProperty] = string(sd)
	err = config.GetConfig().Session.DataStore.Repo.UpdateSession(session)
	if err != nil {
		panic(err)
	}

	requestBody = fmt.Sprintf(`{"callbacks":[{"name":"otp", "value": "%v"},{"name":"action", "value": "%v"}]}`, "1234", "check")
	request = httptest.NewRequest("POST", authUrl, bytes.NewBuffer([]byte(requestBody)))
	request.AddCookie(flowCookie)
	cbReq = &callbacks.Request{}
	resp = executeRequest(t, request, cbReq)
	cookie, err := GetCookieValue("GortasSession", resp.Cookies())
	assert.NotEmpty(t, cookie)
	assert.NoError(t, err)
}

func TestOTPAuthMagicLink(t *testing.T) {
	const authUrl = "http://localhost/gortas/v1/auth/otp"
	const validPhone = "5551112233"

	request := httptest.NewRequest("GET", authUrl, nil)
	cbReq := &callbacks.Request{}
	resp := executeRequest(t, request, cbReq)
	assert.Equal(t, "phone", cbReq.Module)
	assert.Equal(t, 1, len(cbReq.Callbacks))
	assert.Equal(t, "phone", cbReq.Callbacks[0].Name)

	flowId, _ := GetCookieValue(state.FlowCookieName, resp.Cookies())

	flowCookie := &http.Cookie{
		Name:  state.FlowCookieName,
		Value: flowId,
	}

	//send valid phone
	requestBody := fmt.Sprintf(`{"callbacks":[{"name":"phone", "value": "%v"}]}`, validPhone)
	request = httptest.NewRequest("POST", authUrl, bytes.NewBuffer([]byte(requestBody)))
	request.AddCookie(flowCookie)

	cbReq = &callbacks.Request{}
	executeRequest(t, request, cbReq)
	assert.Equal(t, "otp", cbReq.Module)
	assert.Equal(t, 2, len(cbReq.Callbacks))
	assert.Equal(t, "otp", cbReq.Callbacks[0].Name)
	assert.Equal(t, "action", cbReq.Callbacks[1].Name)

	ms, err := otp.GetSender("test", make(map[string]interface{}, 0))
	assert.NoError(t, err)
	ts := ms.(*otp.TestSender)
	msg := ts.Messages[validPhone]
	msgCode := strings.Split(msg, "link code")

	request = httptest.NewRequest("GET", authUrl+"?code="+strings.TrimSpace(msgCode[1]), nil)
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
	response := recorder.Body.String()
	fmt.Println(response)
	err := json.Unmarshal([]byte(response), res)
	assert.NoError(t, err)
	return recorder.Result()
}
