package common

import (
	"github.com/qingwave/weave/pkg/model"
	"github.com/qingwave/weave/pkg/utils/request"

	"github.com/gin-gonic/gin"
)

func GetUser(c *gin.Context) *model.User {
	if c == nil {
		return nil
	}

	val, ok := c.Get(UserContextKey)
	if !ok {
		return nil
	}

	user, ok := val.(*model.User)
	if !ok {
		return nil
	}

	return user
}

func SetRequestInfo(c *gin.Context, ri *request.RequestInfo) {
	if c == nil || ri == nil {
		return
	}

	c.Set(RequestInfoContextKey, ri)
}

func GetRequestInfo(c *gin.Context) *request.RequestInfo {
	if c == nil {
		return nil
	}

	val, ok := c.Get(RequestInfoContextKey)
	if !ok {
		return nil
	}

	ri, ok := val.(*request.RequestInfo)
	if !ok {
		return nil
	}

	return ri
}
