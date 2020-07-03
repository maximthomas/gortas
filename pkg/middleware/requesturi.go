package middleware

import (
	"github.com/gin-gonic/gin"
)

const requestURIKey = "request.uri"

func GetRequestURI(c *gin.Context) string {
	requestURI, ok := c.Get(requestURIKey)
	if ok {
		return requestURI.(string)
	} else {
		return c.Request.RequestURI
	}
}
func NewRequestURIMiddleware() gin.HandlerFunc {
	return requestURIMiddleware{}.build()
}

type requestURIMiddleware struct {
}

func (r requestURIMiddleware) build() gin.HandlerFunc {
	return func(c *gin.Context) {
		scheme := r.getScheme(c)
		host := r.getHost(c)
		path := r.getPath(c)
		c.Set(requestURIKey, scheme+host+path)
		c.Next()
	}
}

func (r requestURIMiddleware) getScheme(c *gin.Context) string {
	if r.getHost(c) != "" {
		if c.Request.TLS != nil {
			return "https://"
		} else {
			return "http://"
		}
	}
	return ""
}

func (r requestURIMiddleware) getHost(c *gin.Context) string {
	return c.Request.Host
}

func (r requestURIMiddleware) getPath(c *gin.Context) string {
	return c.Request.RequestURI
}
