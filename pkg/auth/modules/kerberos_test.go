package modules

import (
	"log"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/maximthomas/gortas/pkg/auth/state"
)

func TestKerberos(t *testing.T) {

	b := BaseAuthModule{
		Properties: map[string]interface{}{
			keyTabDataProperty:       testdata.KEYTAB_TESTUSER1_TEST_GOKRB5,
			servicePrincipalProperty: "HTTP/authservice@ADKERBEROS",
		},
	}

	m := newKerberosModule(b)
	k, _ := m.(*Kerberos)

	t.Run("Test request negotiate", func(t *testing.T) {

		recorder := httptest.NewRecorder()
		k.req = httptest.NewRequest("GET", "/login", nil)
		k.w = recorder
		fs := &state.FlowState{}

		status, cbs, err := k.Process(fs)

		assert.NoError(t, err)
		log.Print(status, cbs, err)
		assert.Equal(t, 1, len(cbs))
		assert.Equal(t, "httpstatus", cbs[0].Name)
		assert.Equal(t, "Negotiate", cbs[0].Properties["WWW-Authenticate"])

		assert.Equal(t, state.InProgress, status)
	})

	t.Run("Test failed authentication", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/login", nil)
		req.Header.Add("Authorization", "Negotiate bad token")
		k.req = req
		k.w = httptest.NewRecorder()
		fs := &state.FlowState{}

		status, cbs, err := k.Process(fs)

		log.Print(status, cbs, err)

		assert.Error(t, err)
	})
}
