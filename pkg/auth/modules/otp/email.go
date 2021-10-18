package otp

import (
	"crypto/tls"
	"time"

	"github.com/mitchellh/mapstructure"
	mail "github.com/xhit/go-simple-mail/v2"
)

type EmailSender struct {
	From    string
	Subject string
	server  *mail.SMTPServer
}

type smtpProperties struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	Subject  string
}

func init() {
	RegisterSender("email", NewEmailSender)
}

func NewEmailSender(props map[string]interface{}) (Sender, error) {
	var sp smtpProperties
	var sender Sender
	err := mapstructure.Decode(props, &sp)
	if err != nil {
		return sender, err
	}

	server := mail.NewSMTPClient()

	server.Host = sp.Host
	server.Port = sp.Port
	server.Username = sp.Username
	server.Password = sp.Password
	server.Encryption = mail.EncryptionNone

	server.KeepAlive = false

	server.ConnectTimeout = 5 * time.Second
	server.SendTimeout = 5 * time.Second

	server.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	return EmailSender{server: server, From: sp.From, Subject: sp.Subject}, nil
}

func (es EmailSender) Send(to string, text string) error {

	smtpClient, err := es.server.Connect()

	if err != nil {
		return err
	}

	email := mail.NewMSG()
	email.SetFrom(es.From).
		AddTo(to).
		SetSubject(es.Subject)

	email.SetBody(mail.TextHTML, text)

	if email.Error != nil {
		return email.Error
	}

	// Call Send and pass the client
	err = email.Send(smtpClient)
	if err != nil {
		return err
	}

	return nil
}
