package controller

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/config"
	"github.com/stretchr/testify/assert"
)

func init() {
	conf := config.Config{}
	config.SetConfig(&conf)
}

func TestGenerateResponse(t *testing.T) {

	type cookie struct {
		name  string
		value string
	}
	type header struct {
		name  string
		value string
	}
	tests := []struct {
		name            string
		cbResp          callbacks.Response
		err             error
		expectedStatus  int
		expectedBody    string
		expectedCookies []cookie
		expectedHeaders []header
	}{
		{
			name:           "auth error",
			cbResp:         callbacks.Response{},
			err:            errors.New("authError"),
			expectedStatus: 401,
			expectedBody:   `{"status":"fail"}`,
		},
		{
			name: "auth in progress",
			cbResp: callbacks.Response{
				Module: "login",
				Callbacks: []callbacks.Callback{
					{Type: "text", Name: "login", Value: ""},
					{Type: "password", Name: "password", Value: ""},
				},
				FlowID: "test-flow-id",
			},
			err:            nil,
			expectedStatus: 200,
			expectedBody: `{"module":"login","callbacks":[{"name":"login","type":"text","value":""},` +
				`{"name":"password","type":"password","value":""}],"flowId":"test-flow-id"}`,
			expectedCookies: []cookie{
				{
					name:  "GortasAuthFlow",
					value: "test-flow-id",
				},
			},
		},
		{
			name: "auth in progress with httpcallback",
			cbResp: callbacks.Response{
				Module: "kerberos",
				Callbacks: []callbacks.Callback{
					{Type: "text", Name: "login", Value: ""},
					{Type: "httpstatus", Name: "httpstatus", Value: "401", Properties: map[string]string{"Authenticate": "WWW-Negotiate"}},
				},
				FlowID: "test-flow-id",
			},
			err:            nil,
			expectedStatus: 401,
			expectedBody:   `{"module":"kerberos","callbacks":[{"name":"login","type":"text","value":""}],"flowId":"test-flow-id"}`,
			expectedCookies: []cookie{
				{
					name:  "GortasAuthFlow",
					value: "test-flow-id",
				},
			},
			expectedHeaders: []header{
				{
					name: "Authenticate", value: "WWW-Negotiate",
				},
			},
		},
		{
			name: "auth succeed",
			cbResp: callbacks.Response{
				Token: "test-token",
				Type:  "Bearer",
			},
			err:            nil,
			expectedStatus: 200,
			expectedBody:   `{"token":"test-token","type":"Bearer"}`,
			expectedCookies: []cookie{
				{
					name:  "GortasSession",
					value: "test-token",
				},
			},
		},
	}

	var getCookie = func(name string, cookies []*http.Cookie) *http.Cookie {
		for _, c := range cookies {
			if c.Name == name {
				return c
			}
		}
		return nil
	}

	ac := NewAuthController()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			ac.generateResponse(c, &tt.cbResp, tt.err)
			resp := recorder.Result()
			defer resp.Body.Close()
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			assert.Equal(t, tt.expectedBody, recorder.Body.String())
			for _, ec := range tt.expectedCookies {
				c := getCookie(ec.name, resp.Cookies())
				assert.NotNil(t, c)
				assert.Equal(t, ec.value, c.Value)
			}
			for _, eh := range tt.expectedHeaders {
				assert.Equal(t, eh.value, resp.Header.Get(eh.name))
			}

		})
	}

}
