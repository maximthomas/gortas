package modules

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/constants"
	"github.com/maximthomas/gortas/pkg/auth/modules/otp"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/maximthomas/gortas/pkg/crypt"
	"github.com/maximthomas/gortas/pkg/models"
	"github.com/maximthomas/gortas/pkg/repo"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewOTP(t *testing.T) {
	m := getOTPModule(t)
	assert.Equal(t, 4, m.OtpLength)
	assert.Equal(t, false, m.UseLetters)
	assert.Equal(t, true, m.UseDigits)
	assert.Equal(t, 180, m.OtpTimeoutSec)
	assert.Equal(t, 90, m.OtpResendSec)
	assert.Equal(t, 5, m.OtpRetryCount)
}

func TestProcess(t *testing.T) {
	m := getOTPModule(t)
	var fs state.FlowState
	status, cbs, err := m.Process(&fs)
	assert.NoError(t, err)
	assert.Equal(t, state.IN_PROGRESS, status)
	assert.Equal(t, 2, len(cbs))

	//check otp callback
	otpCb := cbs[0]
	assert.Equal(t, "otp", otpCb.Name)
	assert.Equal(t, "180", otpCb.Properties["timeoutSec"]) //TODO to int values
	assert.Equal(t, "90", otpCb.Properties["resendSec"])
	assert.Equal(t, "5", otpCb.Properties["retryCount"])

	//check action callback
	actionCb := cbs[1]
	assert.Equal(t, "action", actionCb.Name)
	assert.Equal(t, callbacks.TypeActions, actionCb.Type)
}

func TestProcess_MagicLink(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	keyStr := base64.StdEncoding.EncodeToString(key)
	conf := config.Config{}
	conf.Session.DataStore.Repo = repo.NewInMemorySessionRepository(logrus.New())
	conf.EncryptionKey = keyStr
	config.SetConfig(conf)

	sessionId := "test_session"
	encrypted, err := crypt.EncryptWithConfig(sessionId)
	assert.NoError(t, err)
	sess := models.Session{}
	sess.Properties = make(map[string]string, 1)
	sess.Properties[constants.FlowStateSessionProperty] = "{}"
	sess.ID = sessionId
	conf.Session.DataStore.Repo.CreateSession(sess)

	m := getOTPModule(t)
	m.req = httptest.NewRequest("GET", "http://localhost/gortas?code="+encrypted, nil)
	m.OtpCheckMagicLink = true
	var fs state.FlowState
	st, _, err := m.Process(&fs)
	assert.NoError(t, err)
	assert.Equal(t, state.PASS, st)
}

func TestGenerateOTP(t *testing.T) {
	m := getOTPModule(t)
	m.generate()
	otp := m.otpState.Otp
	generated := m.otpState.GeneratedAt
	assert.NotEmpty(t, otp)
	assert.Equal(t, 4, len(otp))
	assert.True(t, generated > time.Now().UnixMilli()-10000)
}

func TestProcessCallbacks_CodeExpired(t *testing.T) {
	const testOTP = "1234"
	m := getOTPModule(t)
	m.generate()
	m.otpState.Otp = testOTP
	m.otpState.GeneratedAt = int64(0)
	inCbs := []callbacks.Callback{
		{
			Name:  "otp",
			Value: testOTP,
		},
		{
			Name:  "action",
			Value: "check",
		},
	}
	st, cbs, err := m.ProcessCallbacks(inCbs, nil)
	assert.NoError(t, err)
	assert.Equal(t, state.IN_PROGRESS, st)
	assert.Equal(t, "OTP expired", cbs[0].Error)
}

func TestProcessCallbacks_BadOTP(t *testing.T) {
	const testOTP = "1234"
	m := getOTPModule(t)
	m.generate()
	m.otpState.Otp = testOTP
	m.otpState.GeneratedAt = time.Now().UnixMilli()
	inCbs := []callbacks.Callback{
		{
			Name:  "otp",
			Value: "bad",
		},
		{
			Name:  "action",
			Value: "check",
		},
	}
	st, cbs, err := m.ProcessCallbacks(inCbs, nil)
	assert.NoError(t, err)
	assert.Equal(t, state.IN_PROGRESS, st)
	assert.Equal(t, "Invalid OTP", cbs[0].Error)
	assert.Equal(t, "4", cbs[0].Properties["retryCount"])
}

func TestProcessCallbacks_SendNotAllowed(t *testing.T) {
	m := getOTPModule(t)
	inCbs := []callbacks.Callback{
		{
			Name:  "otp",
			Value: "",
		},
		{
			Name:  "action",
			Value: "send",
		},
	}
	m.otpState.GeneratedAt = time.Now().UnixMilli() - 1000
	var fs state.FlowState
	st, cbs, err := m.ProcessCallbacks(inCbs, &fs)
	assert.NoError(t, err)
	assert.Equal(t, state.IN_PROGRESS, st)
	assert.Equal(t, "Sending not allowed yet", cbs[1].Error)
	resend, err := strconv.Atoi(cbs[0].Properties["resendSec"])
	assert.NoError(t, err, "incorrect converted")
	assert.True(t, resend < 1800 && resend > 0, fmt.Sprintf("resend %v", resend))

}

func TestProcessCallbacks_Send(t *testing.T) {
	const testOTP = "1234"
	m := getOTPModule(t)
	inCbs := []callbacks.Callback{
		{
			Name:  "otp",
			Value: "",
		},
		{
			Name:  "action",
			Value: "send",
		},
	}
	m.otpState.GeneratedAt = int64(1000)
	m.otpState.Otp = testOTP
	st, cbs, err := m.ProcessCallbacks(inCbs, &state.FlowState{})
	assert.NoError(t, err)
	assert.Equal(t, state.IN_PROGRESS, st)
	assert.Empty(t, cbs[1].Error)
	assert.NotEqual(t, testOTP, m.State["otp"])
	otpCb := cbs[0]
	assert.Equal(t, "otp", otpCb.Name)
	assert.Equal(t, "180", otpCb.Properties["timeoutSec"]) //TODO to int values
	assert.Equal(t, "90", otpCb.Properties["resendSec"])
	assert.Equal(t, "5", otpCb.Properties["retryCount"])
}

func TestProcessCallbacks_CodeValid(t *testing.T) {
	const testOTP = "1234"
	m := getOTPModule(t)
	m.generate()
	m.otpState.Otp = testOTP
	m.otpState.GeneratedAt = time.Now().UnixMilli()
	inCbs := []callbacks.Callback{
		{
			Name:  "otp",
			Value: testOTP,
		},
		{
			Name:  "action",
			Value: "check",
		},
	}
	st, cbs, err := m.ProcessCallbacks(inCbs, nil)
	assert.NoError(t, err)
	assert.Equal(t, state.PASS, st)
	assert.Empty(t, cbs[0].Error)
}

func TestGetMessage(t *testing.T) {
	m := getOTPModule(t)
	m.otpState.Otp = "1234"
	msg, err := m.getMessage()
	assert.NoError(t, err)
	const expectedMessage = "Code 1234 valid for 03:00 min"
	assert.Equal(t, expectedMessage, msg)
}

func TestSend(t *testing.T) {
	m := getOTPModule(t)
	err := m.send("1")
	assert.NoError(t, err)
	ts := m.otpSender.(*otp.TestSender)
	assert.Equal(t, 1, len(ts.Messages))
}

func getOTPModule(t *testing.T) *OTP {
	var b = BaseAuthModule{
		State: make(map[string]interface{}, 1),
		Properties: map[string]interface{}{
			"otpLength":          float64(4),
			"useLetters":         false,
			"useDigits":          true,
			"otpTimeoutSec":      float64(180),
			"otpResendSec":       float64(90),
			"otpRetryCount":      float64(5),
			"otpMessageTemplate": "Code {{.OTP}} valid for {{.ValidFor}} min",
			"sender": map[string]interface{}{
				"senderType": "test",
				"properties": map[string]interface{}{
					"host": "localhost",
					"port": 1234,
				},
			},
		},
	}
	am := newOTP(b)
	assert.NotNil(t, am)
	otp, ok := am.(*OTP)
	assert.True(t, ok)
	return otp
}
