package authmodules

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/crypt"
	"github.com/maximthomas/gortas/pkg/models"
	"github.com/skip2/go-qrcode"
)

type QR struct {
	BaseAuthModule
	qrTimeout int64
}

func (q *QR) Process(lss *auth.LoginSessionState, _ *gin.Context) (ms auth.ModuleState, cbs []models.Callback, err error) {

	var qrT int64
	qrTf, ok := q.sharedState["qrT"].(float64)
	if ok {
		qrT = int64(qrTf)
	} else {
		seconds := time.Now().Unix()
		qrT = seconds / q.qrTimeout
		q.sharedState["qrT"] = qrT
	}

	image, err := q.generateQRImage(lss.SessionId, qrT)
	if err != nil {
		return auth.Fail, q.callbacks, err
	}

	q.callbacks[0].Properties["image"] = image
	return auth.InProgress, q.callbacks, err
}

func (q *QR) ProcessCallbacks(_ []models.Callback, lss *auth.LoginSessionState, _ *gin.Context) (ms auth.ModuleState, cbs []models.Callback, err error) {

	uid, ok := q.BaseAuthModule.sharedState["qrUserId"].(string)
	if !ok {
		//check if qr is outdated
		var qrT int64
		qrTf, ok := q.sharedState["qrT"].(float64)
		seconds := time.Now().Unix()
		if ok {
			qrT = int64(qrTf)
		} else {
			qrT = seconds / q.qrTimeout
			q.sharedState["qrT"] = qrT
		}

		newQrT := seconds / q.qrTimeout
		if newQrT > qrT {
			q.sharedState["qrT"] = newQrT
		}

		image, err := q.generateQRImage(lss.SessionId, qrT)
		if err != nil {
			return auth.Fail, cbs, err
		}

		q.callbacks[0].Properties["image"] = image

		return auth.InProgress, q.callbacks, err
	}
	lss.UserId = uid
	return auth.Pass, cbs, err

}

func (q *QR) ValidateCallbacks(_ []models.Callback) error {
	return nil
}

func (q *QR) PostProcess(_ string, _ *auth.LoginSessionState, _ *gin.Context) error {
	return nil
}

func (q *QR) getSecret() (secret string, err error) {
	secret, ok := q.sharedState["secret"].(string)
	if !ok {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			return secret, err
		}
		secret = base64.StdEncoding.EncodeToString([]byte(key))
		q.sharedState["secret"] = secret
	}
	return secret, err
}

func (q *QR) generateQRImage(sessId string, qrT int64) (string, error) {
	var image string
	secret, err := q.getSecret()
	if err != nil {
		return image, err
	}

	h := crypt.MD5(secret + strconv.FormatInt(qrT, 10))
	qrValue := fmt.Sprintf("%s;%s", sessId, h)
	png, err := qrcode.Encode(qrValue, qrcode.Medium, 256)
	if err != nil {
		return image, err
	}

	image = "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(png))
	return image, nil
}

func NewQRModule(base BaseAuthModule) *QR {
	(&base).callbacks = []models.Callback{
		{
			Name:       "qr",
			Type:       "image",
			Prompt:     "Enter QR code",
			Value:      "",
			Properties: map[string]string{},
		},
		{
			Name: "submit",
			Type: "autosubmit",
			Properties: map[string]string{
				"interval": "5",
			},
		},
	}

	qrTimeout := 30
	if qrTimeoutProp, ok := base.properties["qrTimeout"]; ok {
		qrTimeout = qrTimeoutProp.(int)
	}
	return &QR{
		BaseAuthModule: base,
		qrTimeout:      int64(qrTimeout),
	}
}
