package modules

import (
	"log"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/stretchr/testify/assert"
)

func TestQR(t *testing.T) {

	t.Run("Test request new qr", func(t *testing.T) {
		q := getQRModule()
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", "/login", nil)

		lss := &state.FlowState{}
		lss.ID = uuid.New().String()

		status, cbs, err := q.Process(lss)
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
		lss := &state.FlowState{SharedState: map[string]string{}}
		lss.ID = uuid.New().String()
		q.BaseAuthModule.State["qrUserId"] = "ivan"
		ms, _, err := q.ProcessCallbacks(q.Callbacks, lss)
		assert.Equal(t, state.Pass, ms)
		assert.NoError(t, err)
	})

	t.Run("Test process update QR", func(t *testing.T) {
		q := getQRModule()
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/login", nil)
		lss := &state.FlowState{SharedState: map[string]string{}}
		lss.ID = uuid.New().String()
		ms, cbs, err := q.ProcessCallbacks(q.Callbacks, lss)
		assert.Equal(t, state.InProgress, ms)
		assert.NoError(t, err)
		image := cbs[0].Properties["image"]
		assert.NotEmpty(t, image)
	})

}

func getQRModule() *QR {
	b := BaseAuthModule{
		Properties: map[string]interface{}{
			"qrTimeout": 10,
		},
		State: map[string]interface{}{},
	}
	m := newQRModule(b)
	q, _ := m.(*QR)
	return q
}
