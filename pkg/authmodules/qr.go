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

func (q *QR) Process(lss *auth.LoginSessionState, c *gin.Context) (ms auth.ModuleState, cbs []models.Callback, err error) {

	key, err := q.getKey()
	if err != nil {
		return auth.Fail, q.callbacks, err
	}

	qrT, ok := q.sharedState["qrT"].(int64)
	if !ok {
		seconds := time.Now().Unix()
		qrT = seconds / q.qrTimeout
		q.sharedState["qrT"] = qrT
	}
	image, err := q.generateQRImage(lss.SessionId, qrT, key)
	if err != nil {
		return auth.Fail, q.callbacks, err
	}

	q.callbacks[0].Properties["image"] = image
	return auth.InProgress, q.callbacks, err
}

func (q *QR) ProcessCallbacks(inCbs []models.Callback, lss *auth.LoginSessionState, c *gin.Context) (ms auth.ModuleState, cbs []models.Callback, err error) {

	uid, ok := lss.SharedState["qrUserId"]
	if !ok {
		key, err := q.getKey()
		if err != nil {
			return auth.Fail, q.callbacks, err
		}
		//check if qr is outdated
		qrT, ok := q.sharedState["qrT"].(int64)
		seconds := time.Now().Unix()
		if !ok {
			qrT = seconds / q.qrTimeout
			q.sharedState["qrT"] = qrT
		}

		newQrT := seconds / q.qrTimeout
		if newQrT > qrT {
			q.sharedState["qrT"] = newQrT
		}

		image, err := q.generateQRImage(lss.SessionId, qrT, key)
		if err != nil {
			return auth.Fail, cbs, err
		}

		q.callbacks[0].Properties["image"] = image

		return auth.InProgress, q.callbacks, err
	}
	lss.UserId = uid
	return auth.Pass, cbs, err

}

func (q *QR) ValidateCallbacks(cbs []models.Callback) error {
	return q.BaseAuthModule.ValidateCallbacks(cbs)
}

func (q *QR) PostProcess(sessID string, lss *auth.LoginSessionState, c *gin.Context) error {
	return nil
}

func (q *QR) getKey() (key []byte, err error) {
	secret, ok := q.sharedState["secret"].(string)
	if !ok {
		key = make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			return key, err
		}
		secret = base64.StdEncoding.EncodeToString([]byte(key))
		q.sharedState["secret"] = secret
	} else {
		key, err = base64.StdEncoding.DecodeString(secret)
		if err != nil {
			return key, err
		}
	}
	return key, err
}

func (q *QR) generateQRImage(sessId string, qrT int64, key []byte) (string, error) {
	var image string
	qrValue := fmt.Sprintf("%s;%s", sessId, strconv.FormatInt(qrT, 10))

	encrypted, err := crypt.Encrypt(key, qrValue)
	if err != nil {
		return image, err
	}
	png, err := qrcode.Encode(fmt.Sprintf("%s;%s", sessId, encrypted), qrcode.Medium, 256)
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
	}
	return &QR{
		BaseAuthModule: base,
		qrTimeout:      int64(base.properties["qrTimeout"].(int)),
	}
}
