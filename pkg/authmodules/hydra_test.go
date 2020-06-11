package authmodules

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/stretchr/testify/assert"
)

func TestHydra(t *testing.T) {

	var loginChallenge = "12345"

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, loginChallenge, req.URL.Query()["login_challenge"][0])
		if req.Method == http.MethodGet && "/oauth2/auth/requests/login" == req.URL.Path {

			rw.Write([]byte(`{
				"skip": false,
				"subject": "user-id",
				"client": {"id": "test_client"},
				"request_url": "https://hydra/oauth2/auth?client_id=1234&scope=foo+bar&response_type=code",
				"requested_scope": ["foo", "bar"],
				"oidc_context": {"ui_locales": []},
				"context": {}
			}`))
			return
		} else if req.Method == http.MethodPut && "/oauth2/auth/requests/login/accept" == req.URL.Path {
			rw.Write([]byte(`{
				"redirect_to": "https://hydra/"
			}`))
			return
		}

		rw.Write([]byte(`{"ok":"ok"}`))
	}))

	defer server.Close()

	b := BaseAuthModule{
		properties: map[string]interface{}{
			"uri": server.URL,
		},
	}
	h := NewHydraModule(b)
	assert.Equal(t, server.URL, h.URI)

	t.Run("Test process", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", "/login?login_challenge="+loginChallenge, nil)

		lss := &auth.LoginSessionState{}

		status, cbs, err := h.Process(lss, c)

		assert.NoError(t, err)

		log.Print(status, cbs, err)
	})

	t.Run("Test PostProcess", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", "/login?login_challenge="+loginChallenge, nil)

		lss := &auth.LoginSessionState{}

		err := h.PostProcess("sess", lss, c)

		assert.NoError(t, err)
		assert.Equal(t, "https://hydra/", lss.RedirectURI)
	})
}
