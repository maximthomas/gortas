package modules

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/stretchr/testify/assert"
)

func TestHydra(t *testing.T) {

	var loginChallenge = "12345"

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, loginChallenge, req.URL.Query()["login_challenge"][0])
		if req.Method == http.MethodGet && req.URL.Path == "/oauth2/auth/requests/login" {

			_, _ = rw.Write([]byte(`{
				"skip": false,
				"subject": "user-id",
				"client": {"id": "test_client"},
				"request_url": "https://hydra/oauth2/auth?client_id=1234&scope=foo+bar&response_type=code",
				"requested_scope": ["foo", "bar"],
				"oidc_context": {"ui_locales": []},
				"context": {}
			}`))
			return
		} else if req.Method == http.MethodPut && req.URL.Path == "/oauth2/auth/requests/login/accept" {
			_, _ = rw.Write([]byte(`{
				"redirect_to": "https://hydra/"
			}`))
			return
		}

		_, _ = rw.Write([]byte(`{"ok":"ok"}`))
	}))

	defer server.Close()

	b := BaseAuthModule{
		Properties: map[string]interface{}{
			"uri": server.URL,
		},
	}
	am := newHydraModule(b)
	h, _ := am.(*Hydra)

	assert.Equal(t, server.URL, h.URI)

	t.Run("Test process", func(t *testing.T) {
		h.req = httptest.NewRequest("GET", "/login?login_challenge="+loginChallenge, nil)
		h.w = httptest.NewRecorder()
		fs := &state.FlowState{}

		status, cbs, err := h.Process(fs)

		assert.NoError(t, err)

		log.Print(status, cbs, err)
	})

	t.Run("Test PostProcess", func(t *testing.T) {
		h.req = httptest.NewRequest("GET", "/login?login_challenge="+loginChallenge, nil)
		h.w = httptest.NewRecorder()

		fs := &state.FlowState{}

		err := h.PostProcess(fs)

		assert.NoError(t, err)
		assert.Equal(t, "https://hydra/", fs.RedirectURI)
	})
}
