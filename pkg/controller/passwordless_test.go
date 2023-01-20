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
	"github.com/maximthomas/gortas/pkg/auth/state"
	"github.com/maximthomas/gortas/pkg/session"
	"github.com/maximthomas/gortas/pkg/user"
	"github.com/stretchr/testify/assert"
)

type qrTestCaseArgs struct {
	session interface{}
}
type qrTestCaseWant struct {
	code int
}
type qrTestCase struct {
	name string
	args qrTestCaseArgs
	want qrTestCaseWant
}

var qrTests = []qrTestCase{
	{
		"no session",
		qrTestCaseArgs{
			session: nil,
		},
		qrTestCaseWant{
			code: http.StatusUnauthorized,
		},
	},
	{
		"no valid user in session",
		qrTestCaseArgs{
			session: session.Session{
				ID:        uuid.New().String(),
				CreatedAt: time.Time{},
				Properties: map[string]string{
					"sub":   "bad",
					"realm": "staff",
				},
			},
		},
		qrTestCaseWant{
			code: http.StatusUnauthorized,
		},
	},
	{
		"valid user in session",
		qrTestCaseArgs{
			session: session.Session{
				ID:        uuid.New().String(),
				CreatedAt: time.Time{},
				Properties: map[string]string{
					"sub":   "user1",
					"realm": "staff",
				},
			},
		},
		qrTestCaseWant{
			code: http.StatusOK,
		},
	},
}

func TestPasswordlessServicesController_RegisterGenerateQR(t *testing.T) {
	pc := NewPasswordlessServicesController(&conf)

	for _, tt := range qrTests {
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
	pc := NewPasswordlessServicesController(&conf)
	type args struct {
		session interface{}
	}
	type want struct {
		code int
	}

	for _, tt := range qrTests {
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
	t.Skip() //TODO implement test
	badSess := session.Session{
		ID:         uuid.New().String(),
		CreatedAt:  time.Now(),
		Properties: nil,
	}
	_, err := session.GetSessionService().CreateSession(badSess)
	assert.NoError(t, err)

	lss := state.FlowState{
		Modules: []state.FlowStateModuleInfo{
			{
				ID:         "",
				Type:       "qr",
				Properties: nil,
				Status:     state.IN_PROGRESS,
				State:      map[string]interface{}{},
			},
		},
		SharedState: map[string]string{},
		UserID:      "",
		ID:          "",
		RedirectURI: "",
	}
	lssBytes, _ := json.Marshal(lss)
	validSess := session.Session{
		ID:        uuid.New().String(),
		CreatedAt: time.Now(),
		Properties: map[string]string{
			"lss": string(lssBytes),
		},
	}
	_, err = session.GetSessionService().CreateSession(validSess)
	assert.NoError(t, err)

	us := user.GetUserService()
	u, _ := us.GetUser("user1")
	u.Properties = map[string]string{
		"passwordless.qr": `{"secret": "s3cr3t"}`,
	}
	err = us.UpdateUser(u)
	assert.NoError(t, err)

	pc := NewPasswordlessServicesController(&conf)
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
				body: fmt.Sprintf(`{"sid":"%q","uid":"bad","realm":"staff","secret":"s3cr3t"}`, validSess.ID),
			},
			want: want{
				code:       http.StatusUnauthorized,
				errMessage: "error updating user",
			},
		},
		{
			name: "user not bound",
			args: args{
				body: fmt.Sprintf(`{"sid":"%q","uid":"user2","realm":"staff","secret":"s3cr3t"}`, validSess.ID),
			},
			want: want{
				code:       http.StatusUnauthorized,
				errMessage: "the user is not bound to QR",
			},
		},
		{
			name: "secret does not match",
			args: args{
				body: fmt.Sprintf(`{"sid":"%q","uid":"user1","realm":"staff","secret":"secret"}`, validSess.ID),
			},
			want: want{
				code:       http.StatusUnauthorized,
				errMessage: "the user is not bound to QR",
			},
		},

		{
			name: "bad authentication session",
			args: args{
				body: fmt.Sprintf(`{"sid":"%q","uid":"user1","realm":"staff","secret":"s3cr3t"}`, badSess.ID),
			},
			want: want{
				code:       http.StatusUnauthorized,
				errMessage: "there is no valid authentication session",
			},
		},
		{
			name: "valid authentication session",
			args: args{
				body: fmt.Sprintf(`{"sid":"%q","uid":"user1","realm":"staff","secret":"s3cr3t"}`, validSess.ID),
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
			var respJSON = make(map[string]interface{})
			err := json.Unmarshal(recorder.Body.Bytes(), &respJSON)
			assert.NoError(t, err)
			if tt.want.errMessage != "" {
				assert.Equal(t, respJSON["error"], tt.want.errMessage)
			}
		})
	}
}
