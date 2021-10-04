package modules

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/pkg/errors"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/maximthomas/gortas/pkg/auth/callbacks"
	"github.com/maximthomas/gortas/pkg/auth/state"
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
	ctxCredentials           = "github.com/jcmturner/gokrb5/v8/ctxCredentials"
)

var outCallback = []callbacks.Callback{
	{
		Name:  "httpstatus",
		Value: "401",
		Properties: map[string]string{
			spnego.HTTPHeaderAuthResponse: spnego.HTTPHeaderAuthResponseValueKey,
		},
	},
}

func init() {
	RegisterModule("kerberos", newKerberosModule)
}

func newKerberosModule(base BaseAuthModule) AuthModule {
	k := &Kerberos{
		BaseAuthModule: base,
	}
	var kt *keytab.Keytab
	var err error
	if ktFileProp, ok := k.BaseAuthModule.Properties[keyTabFileProperty]; ok {
		ktFile, _ := ktFileProp.(string)
		kt, err = keytab.Load(ktFile)
		if err != nil {
			panic(err) // If the "krb5.keytab" file is not available the application will show an error message.
		}
	} else if ktDataProp, ok := k.BaseAuthModule.Properties[keyTabDataProperty]; ok {
		ktData := ktDataProp.(string)
		b, _ := hex.DecodeString(ktData)
		kt = keytab.New()
		err = kt.Unmarshal(b)
		if err != nil {
			panic(err)
		}
	}
	k.kt = kt
	if spProp, ok := k.BaseAuthModule.Properties[servicePrincipalProperty]; ok {
		k.servicePrincipal = spProp.(string)
	}

	return k
}

func (k *Kerberos) Process(fs *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {

	servicePrincipal := k.servicePrincipal
	kt := k.kt
	log.Print(kt)
	if err != nil {
		panic(err) // If the "krb5.keytab" file is not available the application will show an error message.
	}
	r := k.req
	s := strings.SplitN(r.Header.Get(spnego.HTTPHeaderAuthRequest), " ", 2)
	if len(s) != 2 || s[0] != spnego.HTTPHeaderAuthResponseValueKey {
		return state.IN_PROGRESS, outCallback, err
	}

	settings := service.KeytabPrincipal(servicePrincipal)
	// Set up the SPNEGO GSS-API mechanism
	var spnegoMech *spnego.SPNEGO
	h, err := types.GetHostAddress(k.req.RemoteAddr)
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
		// Authentication successful; get user's credentials from the context

		id := ctx.Value(ctxCredentials).(*credentials.Credentials)
		fs.UserId = id.UserName()

		log.Printf("%s %s@%s - SPNEGO authentication succeeded", r.RemoteAddr, id.UserName(), id.Domain())

		return state.PASS, k.Callbacks, err

	} else {
		errText := fmt.Sprintf("%s - SPNEGO Kerberos authentication failed", r.RemoteAddr)
		log.Print(errText)
		return ms, cbs, errors.New(errText)
	}
}

func (k *Kerberos) ProcessCallbacks(_ []callbacks.Callback, _ *state.FlowState) (ms state.ModuleStatus, cbs []callbacks.Callback, err error) {
	return state.IN_PROGRESS, outCallback, err
}

func (k *Kerberos) ValidateCallbacks(cbs []callbacks.Callback) error {
	return k.BaseAuthModule.ValidateCallbacks(cbs)
}

func (k *Kerberos) PostProcess(_ *state.FlowState) error {
	return nil
}
