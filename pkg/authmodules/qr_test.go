package authmodules

import (
	"log"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/stretchr/testify/assert"
)

func TestQR(t *testing.T) {

	t.Run("Test request new qr", func(t *testing.T) {
		q := getQRModule()
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", "/login", nil)

		lss := &auth.LoginSessionState{}
		lss.SessionId = uuid.New().String()

		status, cbs, err := q.Process(lss, c)
		img, ok := cbs[0].Properties["image"]
		assert.True(t, ok)
		assert.NotEmpty(t, img)
		log.Print(status, cbs, err)
	})

	t.Run("Test process successful auth", func(t *testing.T) {
		q := getQRModule()
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/login", nil)
		lss := &auth.LoginSessionState{SharedState: map[string]string{}}
		lss.SessionId = uuid.New().String()
		q.BaseAuthModule.sharedState["qrUserId"] = "ivan"
		ms, _, err := q.ProcessCallbacks(q.callbacks, lss, c)
		assert.Equal(t, auth.Pass, ms)
		assert.NoError(t, err)
	})

	t.Run("Test process update QR", func(t *testing.T) {
		q := getQRModule()
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/login", nil)
		lss := &auth.LoginSessionState{SharedState: map[string]string{}}
		lss.SessionId = uuid.New().String()
		ms, cbs, err := q.ProcessCallbacks(q.callbacks, lss, c)
		assert.Equal(t, auth.InProgress, ms)
		assert.NoError(t, err)
		image, _ := cbs[0].Properties["image"]
		assert.NotEmpty(t, image)
	})

}

func getQRModule() *QR {
	b := BaseAuthModule{
		properties: map[string]interface{}{
			"qrTimeout": 10,
		},
		sharedState: map[string]interface{}{},
	}
	return NewQRModule(b)
}
