package controller

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/qingwave/weave/pkg/authentication"
	"github.com/qingwave/weave/pkg/authentication/oauth"
	"github.com/qingwave/weave/pkg/common"
	"github.com/qingwave/weave/pkg/model"
)

type AuthController struct {
	jwtService  *authentication.JWTService
	oauthManger *oauth.OAuthManager
}

func NewAuthController(jwtService *authentication.JWTService, oauthManager *oauth.OAuthManager) Controller {
	return &AuthController{
		jwtService:  jwtService,
		oauthManger: oauthManager,
	}
}

// @Summary Login
// @Description User login
// @Accept json
// @Produce json
// @Tags auth
// @Param user body model.AuthUser true "auth user info"
// @Success 200 {object} common.Response{data=model.JWTToken}
// @Router /api/v1/auth/token [post]
func (ac *AuthController) Login(c *gin.Context) {
	auser := new(model.AuthUser)
	if err := c.BindJSON(auser); err != nil {
		common.ResponseFailed(c, http.StatusBadRequest, err)
		return
	}

	user := &model.User{
		ID:   1,
		Name: auser.Name,
	}

	token, err := ac.jwtService.CreateToken(user)
	if err != nil {
		common.ResponseFailed(c, http.StatusInternalServerError, err)
		return
	}

	userJson, err := json.Marshal(user)
	if err != nil {
		common.ResponseFailed(c, http.StatusInternalServerError, err)
		return
	}

	if auser.SetCookie {
		c.SetCookie(common.CookieTokenName, token, 3600*24, "/", "", true, true)
		c.SetCookie(common.CookieLoginUser, string(userJson), 3600*24, "/", "", true, false)
	}

	if auser.ReturnUrl == "" {
		auser.ReturnUrl = "https://jwt-prometheus.mh3cloud.cn"
	}

	common.ResponseSuccess(c, model.JWTToken{
		Token:    token,
		Describe: "set token in Authorization Header, [Authorization: Bearer {token}]",
	})
}

func (ac *AuthController) RegisterRoute(api *gin.RouterGroup) {
	api.POST("/auth/token", ac.Login)
}

func (ac *AuthController) Name() string {
	return "Authentication"
}
