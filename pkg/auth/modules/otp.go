package modules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/constants"
	"github.com/maximthomas/gortas/pkg/auth/modules/otp"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/crypt"
	"github.com/maximthomas/gortas/pkg/session"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
)

const (
	actionSend            = "send"
	actionCheck           = "check"
	otpSenderProperty     = "sender"
	otpMagicLinkParameter = "code"
)

type OTP struct {
	BaseAuthModule
	OtpLength          int
	UseLetters         bool
	UseDigits          bool
	OtpTimeoutSec      int
	OtpResendSec       int
	OtpRetryCount      int
	OtpMessageTemplate string
	OtpCheckMagicLink  bool
	otpState           *otpState
	otpSender          otp.Sender
}

type otpState struct {
	Retries     int
	GeneratedAt int64
	Otp         string
}

type otpSenderProperties struct {
	SenderType string
	Properties map[string]interface{}
}

func (lm *OTP) Process(fs *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {
	defer lm.updateState()

	//TODO add check expired date
	if lm.OtpCheckMagicLink { //TODO refactor move to function and code to constant
		return lm.checkMagicLink(fs)
	}
	lm.generateAndSendOTP(fs)
	return state.IN_PROGRESS, lm.Callbacks, err
}

func (lm *OTP) checkMagicLink(fs *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {

	if lm.req.URL.Query().Get(otpMagicLinkParameter) == "" {
		return state.FAIL, lm.Callbacks, err
	}

	code := lm.req.URL.Query().Get(otpMagicLinkParameter)
	codeDecrypted, err := crypt.DecryptWithConfig(code)
	if err != nil {
		return state.FAIL, lm.Callbacks, err
	}

	codeParts := strings.Split(codeDecrypted, "|")
	sessionId := codeParts[0]
	expired, err := strconv.ParseInt(codeParts[1], 10, 0)
	if err != nil {
		return state.FAIL, lm.Callbacks, err
	}

	if time.Now().UnixMilli() > expired {
		return state.FAIL, lm.Callbacks, errors.New("code link expired")
	}

	sess, err := session.GetSessionService().Repo.GetSession(sessionId)
	if err != nil {
		return state.FAIL, lm.Callbacks, err
	}
	var oldFlowState state.FlowState
	err = json.Unmarshal([]byte(sess.Properties[constants.FlowStateSessionProperty]), &oldFlowState)
	if err != nil {
		return state.FAIL, lm.Callbacks, err
	}
	fs.UserId = oldFlowState.UserId
	for k, v := range oldFlowState.SharedState {
		fs.SharedState[k] = v
	}

	for i, m := range oldFlowState.Modules {
		fs.Modules[i].State = m.State
	}

	return state.PASS, lm.Callbacks, err
}

func (lm *OTP) ProcessCallbacks(inCbs []callbacks.Callback, fs *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {
	defer lm.updateState()
	var otp string
	var action string
	for _, cb := range inCbs {
		switch cb.Name {
		case "otp":
			otp = cb.Value
		case "action":
			action = cb.Value
		}
	}

	if action == actionSend {

		return lm.generateAndSendOTP(fs)
	}
	//TODO move to BaseAuthModule
	cbs = make([]callbacks.Callback, len(lm.Callbacks))
	copy(cbs, lm.Callbacks)

	generatedTime := lm.otpState.GeneratedAt
	expiresAt := generatedTime + (int64)(lm.OtpTimeoutSec*1000)
	if time.Now().UnixMilli() > expiresAt {
		(&cbs[0]).Error = "OTP expired"
		return state.IN_PROGRESS, cbs, err
	}

	generatedOtp := lm.otpState.Otp
	if generatedOtp == "" {
		cbs = lm.Callbacks
		(&cbs[0]).Error = "OTP was not generated"
		return state.IN_PROGRESS, cbs, err
	}

	rc := lm.getRetryCount()
	if rc <= 0 {
		(&cbs[0]).Error = "OTP retries excceded"
		(&cbs[0]).Properties["retryCount"] = strconv.Itoa(rc)
		return state.IN_PROGRESS, cbs, err
	}

	valid := generatedOtp == otp || os.Getenv("GORTAS_OTP_TEST") == otp
	if valid {
		return state.PASS, cbs, err
	} else {
		cbs = lm.Callbacks
		lm.incrementRetries()
		(&cbs[0]).Error = "Invalid OTP"
		lm.updateOTPCallbackProperties(&cbs[0])
		return state.IN_PROGRESS, cbs, err
	}
}

func (lm *OTP) updateState() {
	lm.State["generatedAt"] = lm.otpState.GeneratedAt
	lm.State["otp"] = lm.otpState.Otp
	lm.State["retries"] = lm.otpState.Retries
}

func (lm *OTP) generateAndSendOTP(fs *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {
	cbs = make([]callbacks.Callback, len(lm.Callbacks))
	copy(cbs, lm.Callbacks)
	generatedAt := lm.otpState.GeneratedAt
	//check if send allowed
	if generatedAt > time.Now().UnixMilli()-int64(lm.OtpResendSec)*1000 {
		(&cbs[1]).Error = "Sending not allowed yet"
		lm.updateOTPCallbackProperties(&cbs[0])
		return state.IN_PROGRESS, cbs, err
	}

	err = lm.generate()
	if err != nil {
		return state.FAIL, cbs, err
	}
	err = lm.send(fs)
	if err != nil {
		return state.FAIL, cbs, err
	}
	lm.updateOTPCallbackProperties(&cbs[0])
	return state.IN_PROGRESS, cbs, err
}

func (lm *OTP) generate() error {
	otp, err := crypt.RandomString(lm.OtpLength, lm.UseLetters, lm.UseDigits)
	if err != nil {
		return errors.Wrap(err, "error generating OTP")
	}

	lm.otpState.Otp = otp
	lm.otpState.GeneratedAt = time.Now().UnixMilli()
	return nil
}

func (lm *OTP) send(fs *state.FlowState) error {
	msg, err := lm.getMessage(fs)
	if err != nil {
		return errors.Wrap(err, "error generating message")
	}
	err = lm.otpSender.Send(fs.UserId, msg)
	if err != nil {
		return errors.Wrap(err, "error sending message")
	}
	return nil

}

// TODO add authentication link
func (lm *OTP) getMessage(fs *state.FlowState) (string, error) {
	tmpl, err := template.New("message").Parse(lm.OtpMessageTemplate)
	if err != nil {
		return "", err
	}

	minutes := lm.OtpTimeoutSec / 60
	seconds := lm.OtpTimeoutSec % 60
	otpExpiresAt := time.Now().UnixMilli() + int64(lm.OtpTimeoutSec*1000)

	otpTimeoutFormatted := fmt.Sprintf("%02d:%02d", minutes, seconds)
	magicLink, err := crypt.EncryptWithConfig(fs.Id + "|" + strconv.FormatInt(otpExpiresAt, 10))
	if err != nil {
		return "", err
	}

	otpData := struct {
		OTP       string
		ValidFor  string
		MagicLink string
	}{
		OTP:       lm.otpState.Otp,
		ValidFor:  otpTimeoutFormatted,
		MagicLink: magicLink,
	}

	var b bytes.Buffer
	tmpl.Execute(&b, otpData)

	return b.String(), nil
}

func (lm *OTP) updateOTPCallbackProperties(cb *callbacks.Callback) {
	rc := lm.getRetryCount()

	generatedAt := lm.otpState.GeneratedAt

	sinceGeneratedSec := (time.Now().UnixMilli() - generatedAt) / 1000

	rs := lm.OtpResendSec - int(sinceGeneratedSec)
	ts := lm.OtpTimeoutSec - int(sinceGeneratedSec)
	cb.Properties["retryCount"] = strconv.Itoa(rc)
	cb.Properties["resendSec"] = strconv.Itoa(rs)
	cb.Properties["timeoutSec"] = strconv.Itoa(ts)
}

func (lm *OTP) incrementRetries() {
	lm.otpState.Retries++
}

// TODO deal with retry count and retries to eliminate confusion
func (lm *OTP) getRetryCount() int {
	return lm.OtpRetryCount - lm.otpState.Retries
}

func (lm *OTP) ValidateCallbacks(cbs []callbacks.Callback) error {
	return lm.BaseAuthModule.ValidateCallbacks(cbs)
}

func (lm *OTP) PostProcess(_ *state.FlowState) error {
	return nil
}

func init() {
	RegisterModule("otp", newOTP)
}

func newOTP(base BaseAuthModule) AuthModule {

	var om OTP
	err := mapstructure.Decode(base.Properties, &om)
	if err != nil {
		panic(err) //TODO add error processing
	}

	(&base).Callbacks = []callbacks.Callback{
		{
			Name:     "otp",
			Type:     callbacks.TypeText,
			Prompt:   "One Time Password",
			Value:    "",
			Required: true,
			Properties: map[string]string{
				"timeoutSec": strconv.Itoa(om.OtpTimeoutSec),
				"resendSec":  strconv.Itoa(om.OtpResendSec),
				"retryCount": strconv.Itoa(om.OtpRetryCount),
			},
		},
		{
			Name:     "action",
			Type:     callbacks.TypeActions,
			Required: true,
			Value:    "check",
			Properties: map[string]string{
				"values":        "send|check", //TODO add Camel case
				"skipVerifyFor": "send",
			},
		},
	}

	om.BaseAuthModule = base

	var os otpState
	_ = mapstructure.Decode(base.State, &os)
	om.otpState = &os
	var osp otpSenderProperties
	err = mapstructure.Decode(base.Properties[otpSenderProperty], &osp)
	if err != nil {
		panic(err)
	}
	var sender otp.Sender
	sender, err = otp.GetSender(osp.SenderType, osp.Properties)

	if err != nil {
		panic(err)
	}

	om.otpSender = sender

	return &om
}
