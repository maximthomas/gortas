package authmodules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/models"
)

//Hydra ORY Hydra authenctiaction module
type Hydra struct {
	BaseAuthModule
	URI string //hydra URI
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

func (h *Hydra) Process(s *auth.LoginSessionState, c *gin.Context) (ms auth.ModuleState, cbs []models.Callback, err error) {
	uri := fmt.Sprintf("%s/oauth2/auth/requests/login?login_challenge=%s", h.URI, url.PathEscape(c.Query("login_challenge")))
	resp, err := http.Get(uri)
	if err != nil {
		return auth.Fail, h.callbacks, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	var hld HydraLoginData
	err = json.Unmarshal(body, &hld)
	if err != nil {
		return auth.Fail, h.callbacks, err
	}

	if !hld.Skip {

	}

	return auth.Pass, h.callbacks, err
}

func (h *Hydra) ProcessCallbacks(inCbs []models.Callback, s *auth.LoginSessionState, c *gin.Context) (ms auth.ModuleState, cbs []models.Callback, err error) {
	return h.Process(s, c)
}

func (h *Hydra) ValidateCallbacks(cbs []models.Callback) error {
	return h.BaseAuthModule.ValidateCallbacks(cbs)
}

func (h *Hydra) PostProcess(sessID string, lss *auth.LoginSessionState, c *gin.Context) error {

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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	var hres struct {
		RedirectTo string `json:"redirect_to"`
	}
	err = json.Unmarshal(body, &hres)
	if err != nil {
		return err
	}
	lss.RedirectURI = hres.RedirectTo
	return nil

}

func NewHydraModule(base BaseAuthModule) *Hydra {
	uri, ok := base.properties["uri"].(string)
	if !ok {
		panic("hydra module missing uri property")
	}

	return &Hydra{URI: uri}
}
