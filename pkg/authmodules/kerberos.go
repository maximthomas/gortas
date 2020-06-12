package authmodules

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/models"
	"gopkg.in/jcmturner/goidentity.v3"
	"gopkg.in/jcmturner/gokrb5.v7/gssapi"
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/service"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
	"gopkg.in/jcmturner/gokrb5.v7/types"
)

type Kerberos struct {
	BaseAuthModule
	servicePrincipal string
	kt               *keytab.Keytab
}

const (
	keyTabFileProperty       = "keytabfile"
	keyTabDataProperty       = "keytabdata"
	servicePrincipalProperty = "serviceprincipal"
)

func NewKerberosModule(base BaseAuthModule) *Kerberos {
	k := &Kerberos{
		BaseAuthModule: base,
	}
	var kt *keytab.Keytab
	var err error
	if ktFileProp, ok := k.BaseAuthModule.properties[keyTabFileProperty]; ok {
		ktFile, _ := ktFileProp.(string)
		kt, err = keytab.Load(ktFile)
		if err != nil {
			panic(err) // If the "krb5.keytab" file is not available the application will show an error message.
		}
	} else if ktDataProp, ok := k.BaseAuthModule.properties[keyTabDataProperty]; ok {
		ktData := ktDataProp.(string)
		b, _ := hex.DecodeString(ktData)
		kt = keytab.New()
		err = kt.Unmarshal(b)
		if err != nil {
			panic(err)
		}
	}
	k.kt = kt
	if spProp, ok := k.BaseAuthModule.properties[servicePrincipalProperty]; ok {
		k.servicePrincipal = spProp.(string)
	}

	return k
}

func (k *Kerberos) Process(lss *auth.LoginSessionState, c *gin.Context) (ms auth.ModuleState, cbs []models.Callback, err error) {

	servicePrincipal := k.servicePrincipal
	kt := k.kt
	log.Print(kt)
	if err != nil {
		panic(err) // If the "krb5.keytab" file is not available the application will show an error message.
	}

	r := c.Request

	s := strings.SplitN(r.Header.Get(spnego.HTTPHeaderAuthRequest), " ", 2)
	if len(s) != 2 || s[0] != spnego.HTTPHeaderAuthResponseValueKey {
		c.Header(spnego.HTTPHeaderAuthResponse, spnego.HTTPHeaderAuthResponseValueKey)
		c.AbortWithStatus(http.StatusUnauthorized)
		return auth.InProgress, k.callbacks, err
	}

	settings := service.KeytabPrincipal(servicePrincipal)
	// Set up the SPNEGO GSS-API mechanism
	var spnegoMech *spnego.SPNEGO
	h, err := types.GetHostAddress(r.RemoteAddr)
	if err == nil {
		// put in this order so that if the user provides a ClientAddress it will override the one here.
		o := append([]func(*service.Settings){service.ClientAddress(h)}, settings)
		spnegoMech = spnego.SPNEGOService(kt, o...)
	} else {
		spnegoMech = spnego.SPNEGOService(kt)
		log.Printf("%s - SPNEGO could not parse client address: %v", r.RemoteAddr, err)
	}

	// Decode the header into an SPNEGO context token
	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		errText := fmt.Sprintf("%s - SPNEGO error in base64 decoding negotiation header: %v", r.RemoteAddr, err)
		log.Print(errText)
		return ms, cbs, errors.New(errText)
	}
	var st spnego.SPNEGOToken
	err = st.Unmarshal(b)
	if err != nil {
		errText := fmt.Sprintf("%s - SPNEGO error in unmarshaling SPNEGO token: %v", r.RemoteAddr, err)
		log.Print(errText)
		return ms, cbs, errors.New(errText)
	}

	// Validate the context token
	authed, ctx, status := spnegoMech.AcceptSecContext(&st)
	if status.Code != gssapi.StatusComplete && status.Code != gssapi.StatusContinueNeeded {
		errText := fmt.Sprintf("%s - SPNEGO validation error: %v", r.RemoteAddr, status)
		log.Print(errText)
		return ms, cbs, errors.New(errText)
	}
	if status.Code == gssapi.StatusContinueNeeded {
		errText := fmt.Sprintf("%s - SPNEGO GSS-API continue needed", r.RemoteAddr)
		log.Print(errText)
		return ms, cbs, errors.New(errText)
	}
	if authed {
		id := ctx.Value(spnego.CTXKeyCredentials).(goidentity.Identity)
		requestCtx := r.Context()
		requestCtx = context.WithValue(requestCtx, spnego.CTXKeyCredentials, id)
		requestCtx = context.WithValue(requestCtx, spnego.CTXKeyAuthenticated, ctx.Value(spnego.CTXKeyAuthenticated))
		log.Printf("%s %s@%s - SPNEGO authentication succeeded", r.RemoteAddr, id.UserName(), id.Domain())
		lss.UserId = id.UserName()
		return auth.Pass, k.callbacks, err
	} else {
		errText := fmt.Sprintf("%s - SPNEGO Kerberos authentication failed", r.RemoteAddr)
		log.Print(errText)
		return ms, cbs, errors.New(errText)
	}
}

func (k *Kerberos) ProcessCallbacks(_ []models.Callback, _ *auth.LoginSessionState, c *gin.Context) (ms auth.ModuleState, cbs []models.Callback, err error) {
	c.Header(spnego.HTTPHeaderAuthResponse, spnego.HTTPHeaderAuthResponseValueKey)
	c.AbortWithStatus(http.StatusUnauthorized)
	return auth.InProgress, k.callbacks, err
}

func (k *Kerberos) ValidateCallbacks(cbs []models.Callback) error {
	return k.BaseAuthModule.ValidateCallbacks(cbs)
}

func (k *Kerberos) PostProcess(sessID string, lss *auth.LoginSessionState, c *gin.Context) error {
	return nil
}
