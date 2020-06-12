package authmodules

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/models"
)

//Hydra ORY Hydra authentication module
type Hydra struct {
	BaseAuthModule
	URI    string //hydra URI
	client *http.Client
}

type HydraLoginData struct {
	Skip    bool   `json:"skip"`
	Subject string `json:"subject"`
}

type HydraSubject struct {
	Subject     string `json:"subject"`
	Remember    bool   `json:"remember"`
	RememberFor int32  `json:"remember_for"`
	ACR         string `json:"acr"`
}

func (h *Hydra) Process(_ *auth.LoginSessionState, c *gin.Context) (ms auth.ModuleState, cbs []models.Callback, err error) {
	uri := fmt.Sprintf("%s/oauth2/auth/requests/login?login_challenge=%s", h.URI, url.PathEscape(c.Query("login_challenge")))
	resp, err := h.client.Get(uri)
	if err != nil {
		return auth.Fail, h.callbacks, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return auth.Fail, h.callbacks, err
	}
	var hld HydraLoginData
	err = json.Unmarshal(body, &hld)
	if err != nil {
		return auth.Fail, h.callbacks, err
	}

	if !hld.Skip {

	}

	return auth.Pass, h.callbacks, err
}

func (h *Hydra) ProcessCallbacks(_ []models.Callback, s *auth.LoginSessionState, c *gin.Context) (ms auth.ModuleState, cbs []models.Callback, err error) {
	return h.Process(s, c)
}

func (h *Hydra) ValidateCallbacks(cbs []models.Callback) error {
	return h.BaseAuthModule.ValidateCallbacks(cbs)
}

func (h *Hydra) PostProcess(_ string, lss *auth.LoginSessionState, c *gin.Context) error {

	hs := HydraSubject{
		Subject:     lss.UserId,
		Remember:    false,
		RememberFor: 0,
		ACR:         "gortas",
	}

	// marshal User to json
	jsonBody, err := json.Marshal(hs)
	if err != nil {
		return err
	}
	uri := fmt.Sprintf("%s/oauth2/auth/requests/login/accept?login_challenge=%s", h.URI, url.PathEscape(c.Query("login_challenge")))

	req, err := http.NewRequest(http.MethodPut, uri, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := h.client.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
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
	lss.RedirectURI = hRes.RedirectTo
	return nil

}

func NewHydraModule(base BaseAuthModule) *Hydra {
	uri, ok := base.properties["uri"].(string)
	if !ok {
		panic("hydra module missing uri property")
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	return &Hydra{URI: uri, client: client}
}
