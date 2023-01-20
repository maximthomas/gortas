package modules

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/crypt"
	"github.com/skip2/go-qrcode"
)

const (
	qrCodeSize = 256
	secretLen  = 32
)

type QR struct {
	BaseAuthModule
	qrTimeout int64
}

func (q *QR) Process(lss *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {

	var qrT int64
	qrTf, ok := q.State["qrT"].(float64)
	if ok {
		qrT = int64(qrTf)
	} else {
		seconds := time.Now().Unix()
		qrT = seconds / q.qrTimeout
		q.State["qrT"] = qrT
	}

	image, err := q.generateQRImage(lss.ID, qrT)
	if err != nil {
		return state.Fail, q.Callbacks, err
	}

	q.Callbacks[0].Properties["image"] = image
	return state.InProgress, q.Callbacks, err
}

func (q *QR) ProcessCallbacks(_ []callbacks.Callback, lss *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {

	uid, ok := q.BaseAuthModule.State["qrUserId"].(string)
	if !ok {
		// check if qr is outdated
		var qrT int64
		qrTf, ok := q.State["qrT"].(float64)
		seconds := time.Now().Unix()
		if ok {
			qrT = int64(qrTf)
		} else {
			qrT = seconds / q.qrTimeout
			q.State["qrT"] = qrT
		}

		newQrT := seconds / q.qrTimeout
		if newQrT > qrT {
			q.State["qrT"] = newQrT
		}
		var image string
		image, err = q.generateQRImage(lss.ID, qrT)
		if err != nil {
			return state.Fail, cbs, err
		}

		q.Callbacks[0].Properties["image"] = image

		return state.InProgress, q.Callbacks, err
	}
	lss.UserID = uid
	return state.Pass, cbs, err

}

func (q *QR) ValidateCallbacks(_ []callbacks.Callback) error {
	return nil
}

func (q *QR) PostProcess(_ *state.FlowState) error {
	return nil
}

func (q *QR) getSecret() (secret string, err error) {
	secret, ok := q.State["secret"].(string)
	if !ok {

		key := make([]byte, secretLen)
		_, err = rand.Read(key)
		if err != nil {
			return secret, err
		}
		secret = base64.StdEncoding.EncodeToString(key)
		q.State["secret"] = secret
	}
	return secret, err
}

func (q *QR) generateQRImage(sessID string, qrT int64) (string, error) {
	var image string
	secret, err := q.getSecret()
	if err != nil {
		return image, err
	}

	h := crypt.MD5(secret + strconv.FormatInt(qrT, 10))
	qrValue := fmt.Sprintf("?sid=%s;%s&action=login", sessID, h)
	png, err := qrcode.Encode(qrValue, qrcode.Medium, qrCodeSize)
	if err != nil {
		return image, err
	}

	image = "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(png))
	return image, nil
}

func init() {
	RegisterModule("qr", newQRModule)
}

func newQRModule(base BaseAuthModule) AuthModule {
	(&base).Callbacks = []callbacks.Callback{
		{
			Name:       "qr",
			Type:       callbacks.TypeImage,
			Prompt:     "Enter QR code",
			Value:      "",
			Properties: map[string]string{},
		},
		{
			Name: "submit",
			Type: callbacks.TypeAutoSubmit,
			Properties: map[string]string{
				"interval": "5",
			},
		},
	}

	qrTimeout := 30
	if qrTimeoutProp, ok := base.Properties["qrTimeout"]; ok {
		qrTimeout = qrTimeoutProp.(int)
	}
	return &QR{
		BaseAuthModule: base,
		qrTimeout:      int64(qrTimeout),
	}
}
