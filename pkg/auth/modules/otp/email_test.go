//go:build integration

package otp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	emailFrom    = "john@test.com"
	emailSubject = "OTP"
)

func TestSendEmail(t *testing.T) {
	es := getEmailSender(t)
	err := es.Send("test@test.com", "hello email")
	assert.NoError(t, err)
}

func TestCreateEmailSender(t *testing.T) {
	es := getEmailSender(t)
	assert.Equal(t, emailSubject, es.Subject)
	assert.Equal(t, emailFrom, es.From)
}

func getEmailSender(t *testing.T) EmailSender {

	props := map[string]interface{}{
		"Host":     "localhost",
		"Port":     1025,
		"Username": "",
		"Password": "",
		"From":     emailFrom,
		"Subject":  emailSubject,
	}

	s, err := NewEmailSender(props)
	es := s.(EmailSender)
	assert.NoError(t, err)
	assert.NotNil(t, es.server)
	return es
}
