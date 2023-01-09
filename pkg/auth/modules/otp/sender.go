package otp

import (
	"fmt"
	"sync"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Sender interface {
	Send(to string, text string) error
}

var senderRegistry = &sync.Map{}

type senderConstructor func(map[string]interface{}) (Sender, error)

func RegisterSender(id string, constructor senderConstructor) {
	logrus.Infof("registered %v sender", id)
	senderRegistry.Store(id, constructor)
}

func GetSender(id string, props map[string]interface{}) (Sender, error) {
	c, ok := senderRegistry.Load(id)
	if !ok {
		return nil, fmt.Errorf("sender %s does not exists", id)
	}
	s, err := c.(senderConstructor)(props)
	if err != nil {
		return s, errors.Wrapf(err, "error creating sender %s", id)
	}
	return s, err
}

var ts *TestSender

type TestSender struct {
	Host     string
	Port     int
	Messages map[string]string
}

func init() {
	RegisterSender("test", NewTestSender)
}

func NewTestSender(props map[string]interface{}) (Sender, error) {
	if ts != nil {
		return ts, nil
	}
	var newTS TestSender
	err := mapstructure.Decode(props, &newTS)
	if err != nil {
		return nil, err
	}
	ts = &newTS
	ts.Messages = make(map[string]string)
	return ts, nil
}

func (ts *TestSender) Send(to, text string) error {
	ts.Messages[to] = text
	return nil
}
