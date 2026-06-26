package jwt

import (
	"errors"
	"time"

	lib "github.com/golang-jwt/jwt/v5"
)

// AccessClaims 访问令牌载荷，包含用户基础身份信息
type AccessClaims struct {
	UserID   int64  `json:"uid"`
	Username string `json:"usr"`
	RoleID   int64  `json:"rid"`
	lib.RegisteredClaims
}

// RefreshClaims 刷新令牌载荷，仅包含会话ID用于查库验证
type RefreshClaims struct {
	SessionID int64 `json:"sid"`
	lib.RegisteredClaims
}

// GenerateAccess 签发访问令牌，有效期单位为分钟
func GenerateAccess(userID, roleID int64, username, secret string, expMin int) (string, error) {
	claims := &AccessClaims{
		UserID:   userID,
		Username: username,
		RoleID:   roleID,
		RegisteredClaims: lib.RegisteredClaims{
			ExpiresAt: lib.NewNumericDate(time.Now().Add(time.Duration(expMin) * time.Minute)),
			IssuedAt:  lib.NewNumericDate(time.Now()),
			Issuer:    "security-platform",
		},
	}
	return lib.NewWithClaims(lib.SigningMethodHS256, claims).SignedString([]byte(secret))
}

// GenerateRefresh 签发刷新令牌，有效期单位为天
func GenerateRefresh(sessionID int64, secret string, expDay int) (string, error) {
	claims := &RefreshClaims{
		SessionID: sessionID,
		RegisteredClaims: lib.RegisteredClaims{
			ExpiresAt: lib.NewNumericDate(time.Now().Add(time.Duration(expDay) * 24 * time.Hour)),
			IssuedAt:  lib.NewNumericDate(time.Now()),
			Issuer:    "security-platform",
		},
	}
	return lib.NewWithClaims(lib.SigningMethodHS256, claims).SignedString([]byte(secret))
}

// ParseAccess 解析并验证访问令牌
func ParseAccess(tokenStr, secret string) (*AccessClaims, error) {
	token, err := lib.ParseWithClaims(tokenStr, &AccessClaims{}, hmacKeyFunc(secret))
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*AccessClaims)
	if !ok || !token.Valid {
		return nil, errors.New("令牌格式不合法")
	}
	return claims, nil
}

// ParseRefresh 解析并验证刷新令牌
func ParseRefresh(tokenStr, secret string) (*RefreshClaims, error) {
	token, err := lib.ParseWithClaims(tokenStr, &RefreshClaims{}, hmacKeyFunc(secret))
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*RefreshClaims)
	if !ok || !token.Valid {
		return nil, errors.New("刷新令牌格式不合法")
	}
	return claims, nil
}

func hmacKeyFunc(secret string) lib.Keyfunc {
	return func(t *lib.Token) (interface{}, error) {
		if _, ok := t.Method.(*lib.SigningMethodHMAC); !ok {
			return nil, errors.New("不支持的签名算法")
		}
		return []byte(secret), nil
	}
}
