package integration_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	"github.com/stretchr/testify/assert"
)

var privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
var privateKeyStr = string(pem.EncodeToMemory(
	&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	},
))
var (
	flows = map[string]config.Flow{
		"otp": {Modules: []config.Module{
			{
				ID:       "otp_link",
				Type:     "otp",
				Criteria: constants.CriteriaSufficient,
				Properties: map[string]interface{}{
					"otpCheckMagicLink": true,
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

	conf = config.Config{
		Flows: flows,
		Session: session.Config{
			Type:    "stateless",
			Expires: 60000,
			Jwt: session.JWT{
				Issuer:        "http://gortas",
				PrivateKeyPem: privateKeyStr,
			},
		},
		EncryptionKey: "Gb8l9wSZzEjeL2FTRG0k6bBnw7AZ/rBCcZfDDGLVreY=",
	}
	router *gin.Engine
)

const (
	authURL    = "http://localhost/gortas/v1/auth/otp"
	badPhone   = "123"
	validPhone = "5551112233"
)

func init() {
	config.SetConfig(&conf)
	router = server.SetupRouter(&conf)
}

func TestOTPAuth(t *testing.T) {

	flowCookie := initAuth(t)

	// send phone
	requestBody := fmt.Sprintf(`{"callbacks":[{"name":"phone", "value": "%v"}]}`, validPhone)
	request := httptest.NewRequest("POST", authURL, bytes.NewBuffer([]byte(requestBody)))
	request.AddCookie(flowCookie)

	cbReq := &callbacks.Request{}
	executeRequest(t, request, cbReq)
	assert.Equal(t, "otp", cbReq.Module)
	assert.Equal(t, 2, len(cbReq.Callbacks))
	assert.Equal(t, "otp", cbReq.Callbacks[0].Name)
	assert.Equal(t, "action", cbReq.Callbacks[1].Name)

	// send OTP
	sess, _ := session.GetSessionService().GetSession(flowCookie.Value)
	var fs state.FlowState
	err := json.Unmarshal([]byte(sess.Properties[constants.FlowStateSessionProperty]), &fs)
	if err != nil {
		panic(err)
	}
	fs.Modules[2].State["otp"] = "1234"
	sd, _ := json.Marshal(fs)
	sess.Properties[constants.FlowStateSessionProperty] = string(sd)
	err = session.GetSessionService().UpdateSession(sess)
	if err != nil {
		panic(err)
	}

	requestBody = fmt.Sprintf(`{"callbacks":[{"name":"otp", "value": "%v"},{"name":"action", "value": "%v"}]}`, "1234", "check")
	request = httptest.NewRequest("POST", authURL, bytes.NewBuffer([]byte(requestBody)))
	request.AddCookie(flowCookie)
	cbReq = &callbacks.Request{}
	resp := executeRequest(t, request, cbReq)
	cookie, err := GetCookieValue("GortasSession", resp.Cookies())
	assert.NotEmpty(t, cookie)
	assert.NoError(t, err)
}

func TestOTPAuth_invalidPhone(t *testing.T) {
	flowCookie := initAuth(t)
	// send invalid phone
	requestBody := fmt.Sprintf(`{"callbacks":[{"name":"phone", "value": "%v"}]}`, badPhone)

	request := httptest.NewRequest("POST", authURL, bytes.NewBuffer([]byte(requestBody)))
	request.AddCookie(flowCookie)
	cbReq := &callbacks.Request{}
	executeRequest(t, request, cbReq)
	assert.Equal(t, "phone", cbReq.Module)
	assert.Equal(t, 1, len(cbReq.Callbacks))
	assert.Equal(t, "phone", cbReq.Callbacks[0].Name)
	assert.Equal(t, "Phone invalid", cbReq.Callbacks[0].Error)
}

func TestOTPAuth_invalidOtp(t *testing.T) {
	flowCookie := authPhone(validPhone, t)

	//send invalid OTP
	requestBody := fmt.Sprintf(`{"callbacks":[{"name":"otp", "value": "%v"},{"name":"action", "value": "%v"}]}`, "1234", "check")
	request := httptest.NewRequest("POST", authURL, bytes.NewBuffer([]byte(requestBody)))
	request.AddCookie(flowCookie)
	cbReq := &callbacks.Request{}
	executeRequest(t, request, cbReq)
	assert.Equal(t, "Invalid OTP", cbReq.Callbacks[0].Error)
}

func initAuth(t *testing.T) *http.Cookie {
	// init auth
	request := httptest.NewRequest("GET", authURL, nil)
	cbReq := &callbacks.Request{}
	resp := executeRequest(t, request, cbReq)
	assert.Equal(t, "phone", cbReq.Module)
	assert.Equal(t, 1, len(cbReq.Callbacks))
	assert.Equal(t, "phone", cbReq.Callbacks[0].Name)

	cookieVal, _ := GetCookieValue(state.FlowCookieName, resp.Cookies())

	return &http.Cookie{
		Name:  state.FlowCookieName,
		Value: cookieVal,
	}
}

func authPhone(phone string, t *testing.T) *http.Cookie {
	flowCookie := initAuth(t)

	requestBody := fmt.Sprintf(`{"callbacks":[{"name":"phone", "value": "%v"}]}`, validPhone)
	request := httptest.NewRequest("POST", authURL, bytes.NewBuffer([]byte(requestBody)))
	request.AddCookie(flowCookie)

	cbReq := &callbacks.Request{}
	executeRequest(t, request, cbReq)
	return flowCookie
}

func TestOTPAuthMagicLink(t *testing.T) {

	request := httptest.NewRequest("GET", authURL, nil)
	cbReq := &callbacks.Request{}
	resp := executeRequest(t, request, cbReq)
	assert.Equal(t, "phone", cbReq.Module)
	assert.Equal(t, 1, len(cbReq.Callbacks))
	assert.Equal(t, "phone", cbReq.Callbacks[0].Name)

	flowID, _ := GetCookieValue(state.FlowCookieName, resp.Cookies())

	flowCookie := &http.Cookie{
		Name:  state.FlowCookieName,
		Value: flowID,
	}

	//send valid phone
	requestBody := fmt.Sprintf(`{"callbacks":[{"name":"phone", "value": "%v"}]}`, validPhone)
	request = httptest.NewRequest("POST", authURL, bytes.NewBuffer([]byte(requestBody)))
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

	request = httptest.NewRequest("GET", authURL+"?code="+strings.TrimSpace(msgCode[1]), nil)
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
