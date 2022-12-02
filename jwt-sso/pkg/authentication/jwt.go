package authentication

import (
	"crypto/rsa"
	"fmt"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/qingwave/weave/pkg/model"

	"github.com/golang-jwt/jwt/v4"
)

const (
	Issuer = "weave.io"
)

type CustomClaims struct {
	ID    uint   `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

type JWTService struct {
	privateKey     *rsa.PrivateKey
	publicKey      *rsa.PublicKey
	issuer         string
	expireDuration int64
}

func NewJWTService(keyPath string) *JWTService {
	keyData, err := os.ReadFile(path.Join(keyPath, "id_rsa"))
	if err != nil {
		panic(err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		panic(err)
	}

	keyData, _ = os.ReadFile(path.Join(keyPath, "id_rsa.pub"))
	publicKey, _ := jwt.ParseRSAPublicKeyFromPEM(keyData)

	return &JWTService{
		privateKey:     privateKey,
		publicKey:      publicKey,
		issuer:         Issuer,
		expireDuration: int64(7 * 24 * time.Hour.Seconds()),
	}
}

func (s *JWTService) CreateToken(user *model.User) (string, error) {
	if user == nil {
		return "", fmt.Errorf("empty user")
	}

	c := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(s.expireDuration) * time.Second)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-1000 * time.Second)),
		ID:        strconv.Itoa(int(user.ID)),
		Issuer:    "jwt-sso.mh3cloud.cn",
		Subject:   strconv.Itoa(int(user.ID)),
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		CustomClaims{
			Name:             user.Name,
			Email:            user.Email,
			ID:               user.ID,
			RegisteredClaims: c,
		},
	)

	return token.SignedString(s.privateKey)
}

func (s *JWTService) ParseToken(tokenString string) (*model.User, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (i interface{}, err error) {
		return s.publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invaild token")
	}

	user := &model.User{
		ID:    claims.ID,
		Email: claims.Email,
		Name:  claims.Name,
	}

	return user, nil
}
