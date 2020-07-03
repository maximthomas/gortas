package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/maximthomas/gortas/pkg/auth"
	"github.com/maximthomas/gortas/pkg/crypt"
	"github.com/maximthomas/gortas/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestPasswordlessServicesController_RegisterGenerateQR(t *testing.T) {
	pc := NewPasswordlessServicesController(conf)
	type args struct {
		session interface{}
	}
	type want struct {
		code int
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			"no session",
			args{
				session: nil,
			},
			want{
				code: http.StatusUnauthorized,
			},
		},
		{
			"no valid user in session",
			args{
				session: models.Session{
					ID:        uuid.New().String(),
					CreatedAt: time.Time{},
					Properties: map[string]string{
						"sub":   "bad",
						"realm": "staff",
					},
				},
			},
			want{
				code: http.StatusUnauthorized,
			},
		},
		{
			"valid user in session",
			args{
				session: models.Session{
					ID:        uuid.New().String(),
					CreatedAt: time.Time{},
					Properties: map[string]string{
						"sub":   "user1",
						"realm": "staff",
					},
				},
			},
			want{
				code: http.StatusOK,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			if tt.args.session != nil {
				c.Set("session", tt.args.session)
			}
			c.Request = httptest.NewRequest("POST", "/", nil)

			pc.RegisterGenerateQR(c)
			assert.Equal(t, recorder.Code, tt.want.code)
		})
	}
}

func TestPasswordlessServicesController_RegisterConfirmQR(t *testing.T) {
	pc := NewPasswordlessServicesController(conf)
	type args struct {
		session interface{}
	}
	type want struct {
		code int
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			"no session",
			args{
				session: nil,
			},
			want{
				code: http.StatusUnauthorized,
			},
		},
		{
			"no valid user in session",
			args{
				session: models.Session{
					ID:        uuid.New().String(),
					CreatedAt: time.Time{},
					Properties: map[string]string{
						"sub":   "bad",
						"realm": "staff",
					},
				},
			},
			want{
				code: http.StatusUnauthorized,
			},
		},
		{
			"valid user in session",
			args{
				session: models.Session{
					ID:        uuid.New().String(),
					CreatedAt: time.Time{},
					Properties: map[string]string{
						"sub":   "user1",
						"realm": "staff",
					},
				},
			},
			want{
				code: http.StatusOK,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Keys = make(map[string]interface{})
			if tt.args.session != nil {
				c.Set("session", tt.args.session)
			}
			c.Request = httptest.NewRequest("POST", "/", nil)

			pc.RegisterConfirmQR(c)

			assert.Equal(t, recorder.Code, tt.want.code)
		})
	}
}

func TestPasswordlessServicesController_AuthQR(t *testing.T) {
	badSess := models.Session{
		ID:         uuid.New().String(),
		CreatedAt:  time.Now(),
		Properties: nil,
	}
	conf.Session.DataStore.Repo.CreateSession(badSess)

	lss := auth.LoginSessionState{
		Modules: []auth.LoginSessionStateModuleInfo{
			{
				Id:          "",
				Type:        "qr",
				Properties:  nil,
				State:       auth.InProgress,
				SharedState: map[string]interface{}{},
			},
		},
		SharedState: map[string]string{},
		UserId:      "",
		SessionId:   "",
		RedirectURI: "",
	}
	lssBytes, _ := json.Marshal(lss)
	validSess := models.Session{
		ID:        uuid.New().String(),
		CreatedAt: time.Now(),
		Properties: map[string]string{
			"lss": string(lssBytes),
		},
	}
	conf.Session.DataStore.Repo.CreateSession(validSess)

	ur := conf.Authentication.Realms["staff"].UserDataStore.Repo
	user, _ := ur.GetUser("user1")
	user.Properties = map[string]string{
		"passwordless.qr": `{"secret": "s3cr3t"}`,
	}
	ur.UpdateUser(user)

	pc := NewPasswordlessServicesController(conf)
	type args struct {
		body string
	}
	type want struct {
		code       int
		errMessage string
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "bad request body",
			args: args{
				body: "bad",
			},
			want: want{
				code:       http.StatusBadRequest,
				errMessage: "invalid request body",
			},
		},
		{
			name: "no valid session",
			args: args{
				body: `{"sid":"bad","uid":"user1","realm":"staff","secret":"s3cr3t"}`,
			},
			want: want{
				code:       http.StatusUnauthorized,
				errMessage: "there is no valid authentication session",
			},
		},
		{
			name: "no valid user in a repo",
			args: args{
				body: fmt.Sprintf(`{"sid":"%s","uid":"bad","realm":"staff","secret":"s3cr3t"}`, validSess.ID+";"+crypt.MD5("rand")),
			},
			want: want{
				code:       http.StatusUnauthorized,
				errMessage: "error updating user",
			},
		},
		{
			name: "user not bound",
			args: args{
				body: fmt.Sprintf(`{"sid":"%s","uid":"user2","realm":"staff","secret":"s3cr3t"}`, validSess.ID+";"+crypt.MD5("rand")),
			},
			want: want{
				code:       http.StatusUnauthorized,
				errMessage: "the user is not bound to QR",
			},
		},
		{
			name: "secret does not match",
			args: args{
				body: fmt.Sprintf(`{"sid":"%s","uid":"user1","realm":"staff","secret":"secret"}`, validSess.ID+";"+crypt.MD5("rand")),
			},
			want: want{
				code:       http.StatusUnauthorized,
				errMessage: "the user is not bound to QR",
			},
		},

		{
			name: "bad authentication session",
			args: args{
				body: fmt.Sprintf(`{"sid":"%s","uid":"user1","realm":"staff","secret":"s3cr3t"}`, badSess.ID),
			},
			want: want{
				code:       http.StatusUnauthorized,
				errMessage: "there is no valid authentication session",
			},
		},
		{
			name: "valid authentication session",
			args: args{
				body: fmt.Sprintf(`{"sid":"%s","uid":"user1","realm":"staff","secret":"s3cr3t"}`, validSess.ID+";"+crypt.MD5("rand")),
			},
			want: want{
				code: http.StatusOK,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest("POST", "/", strings.NewReader(tt.args.body))
			pc.AuthQR(c)
			assert.Equal(t, tt.want.code, recorder.Code)
			var respJson = make(map[string]interface{})
			err := json.Unmarshal([]byte(recorder.Body.String()), &respJson)
			assert.NoError(t, err)
			if tt.want.errMessage != "" {
				assert.Equal(t, respJson["error"], tt.want.errMessage)
			}
		})
	}
}
