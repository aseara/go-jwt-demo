package controller

import (
	"encoding/json"
	"math/rand"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/qingwave/weave/pkg/authentication"
	"github.com/qingwave/weave/pkg/common"
	"github.com/qingwave/weave/pkg/model"
)

type AuthController struct {
	jwtService *authentication.JWTService
}

func NewAuthController(jwtService *authentication.JWTService) *AuthController {
	return &AuthController{
		jwtService: jwtService,
	}
}

// Login @Summary Login
// @Description User login
// @Accept json
// @Produce json
// @Tags auth
// @Param user body model.AuthUser true "auth user info"
// @Success 200 {object} common.Response{data=model.JWTToken}
// @Router /api/v1/auth/token [post]
func (ac *AuthController) Login(c *gin.Context) {
	au := new(model.AuthUser)
	if err := c.BindJSON(au); err != nil {
		common.ResponseFailed(c, http.StatusBadRequest, err)
		return
	}

	user := &model.User{
		ID:    uint(rand.Intn(3000) + 1000),
		Name:  au.Name,
		Email: au.Email,
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

	if au.SetCookie {
		c.SetCookie(common.CookieTokenName, token, 3600*24, "/", "mh3cloud.cn", false, false)
		c.SetCookie(common.CookieLoginUser, string(userJson), 3600*24, "/", "mh3cloud.cn", false, false)
	}

	common.ResponseSuccess(c, model.JWTToken{
		Token:    token,
		Describe: "set token in Authorization Header, [Authorization: Bearer {token}]",
	})
}

// Logout @Summary Logout
// @Description User logout
// @Produce json
// @Tags auth
// @Success 200 {object} common.Response
// @Router /api/v1/auth/token [delete]
func (ac *AuthController) Logout(c *gin.Context) {
	c.SetCookie(common.CookieTokenName, "", -1, "/", "mh3cloud.cn", false, true)
	c.SetCookie(common.CookieLoginUser, "", -1, "/", "mh3cloud.cn", false, false)
	common.ResponseSuccess(c, nil)
}

func (ac *AuthController) RegisterRoute(api *gin.RouterGroup) {
	api.POST("/auth/token", ac.Login)
	api.DELETE("/auth/token", ac.Logout)
}

func (ac *AuthController) Name() string {
	return "Authentication"
}
