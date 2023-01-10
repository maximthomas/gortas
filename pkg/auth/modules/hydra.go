package modules

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
)

// Hydra ORY Hydra authentication module
type Hydra struct {
	BaseAuthModule
	URI    string //hydra URI
	client *http.Client
}

type hydraLoginData struct {
	Skip    bool   `json:"skip"`
	Subject string `json:"subject"`
}

type hydraSubject struct {
	Subject     string `json:"subject"`
	Remember    bool   `json:"remember"`
	RememberFor int32  `json:"remember_for"`
	ACR         string `json:"acr"`
}

func (h *Hydra) getLoginChallenge() string {
	return url.PathEscape(h.req.URL.Query().Get("login_challenge"))
}

func (h *Hydra) Process(_ *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {
	hydraLoginURL := fmt.Sprintf("%s/oauth2/auth/requests/login?login_challenge=%s", h.URI, h.getLoginChallenge())
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hydraLoginURL, nil)
	if err != nil {
		return state.FAIL, h.Callbacks, fmt.Errorf("Process %v: %v", hydraLoginURL, err)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return state.FAIL, h.Callbacks, fmt.Errorf("Process %v: %v", hydraLoginURL, err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return state.FAIL, h.Callbacks, err
	}
	var hld hydraLoginData
	err = json.Unmarshal(body, &hld)
	if err != nil {
		return state.FAIL, h.Callbacks, err
	}

	return state.PASS, h.Callbacks, err
}

func (h *Hydra) ProcessCallbacks(_ []callbacks.Callback, s *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {
	return h.Process(s)
}

func (h *Hydra) ValidateCallbacks(cbs []callbacks.Callback) error {
	return h.BaseAuthModule.ValidateCallbacks(cbs)
}

func (h *Hydra) PostProcess(fs *state.FlowState) error {

	hs := hydraSubject{
		Subject:     fs.UserID,
		Remember:    false,
		RememberFor: 0,
		ACR:         "gortas",
	}

	// marshal User to json
	jsonBody, err := json.Marshal(hs)
	if err != nil {
		return err
	}
	uri := fmt.Sprintf("%s/oauth2/auth/requests/login/accept?login_challenge=%s", h.URI, h.getLoginChallenge())
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uri, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := h.client.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var hRes struct {
		RedirectTo string `json:"redirect_to"`
	}
	err = json.Unmarshal(body, &hRes)
	if err != nil {
		return err
	}
	fs.RedirectURI = hRes.RedirectTo
	return nil

}

func init() {
	RegisterModule("hydra", newHydraModule)
}

func newHydraModule(base BaseAuthModule) AuthModule {
	skipTLS, _ := base.Properties["skiptls"].(bool)

	uri, ok := base.Properties["uri"].(string)

	if !ok {
		panic("hydra module missing uri property")
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipTLS,
			},
		},
	}

	return &Hydra{URI: uri, client: client}
}
