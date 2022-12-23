package log

import "github.com/sirupsen/logrus"

var logger = logrus.New()

func WithField(key string, value interface{}) *logrus.Entry {
	return logger.WithField(key, value)
}
