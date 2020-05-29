package authmodules

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth"
	"gopkg.in/jcmturner/gokrb5.v7/test/testdata"
)

func TestKerberos(t *testing.T) {
	b := BaseAuthModule{
		properties: map[string]interface{}{
			keyTabDataProperty:       testdata.TESTUSER1_USERKRB5_AD_KEYTAB,
			servicePrincipalProperty: "HTTP/authservice@ADKERBEROS",
		},
	}
	k := NewKerberosModule(b)

	t.Run("Test request negotiate", func(t *testing.T) {

		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", "/login", nil)

		lss := &auth.LoginSessionState{}

		status, cbs, err := k.Process(lss, c)

		log.Print(status, cbs, err)

		assert.NoError(t, err)
		assert.Equal(t, auth.InProgress, status)
		assert.Equal(t, http.StatusUnauthorized, recorder.Code)
		assert.Equal(t, "Negotiate", recorder.Header().Get("WWW-Authenticate"))
	})

	t.Run("Test failed authentication", func(t *testing.T) {

		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", "/login", nil)
		c.Request.Header.Add("Authorization", "Negotiate bad token")

		lss := &auth.LoginSessionState{}

		status, cbs, err := k.Process(lss, c)

		log.Print(status, cbs, err)

		assert.Error(t, err)
	})

}
