package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword 使用bcrypt对密码进行哈希处理，代价因子12
func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(b), err
}

// CheckPassword 验证明文密码与bcrypt哈希是否匹配
func CheckPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// SHA256Hex 计算字符串的SHA256哈希值并以十六进制返回
func SHA256Hex(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// HashAPIKey 对API密钥原文进行SHA256哈希，用于数据库存储
func HashAPIKey(rawKey string) string {
	return SHA256Hex(rawKey)
}

// GenerateRandomHex 生成指定字节数的随机十六进制字符串
func GenerateRandomHex(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("随机数生成失败: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateAPIKey 生成格式为 "sp_<前缀>_<随机串>" 的API密钥
// 返回原始密钥（只展示一次）和前缀（用于展示和检索）
func GenerateAPIKey() (rawKey, prefix string, err error) {
	prefixBytes, err := GenerateRandomHex(4)
	if err != nil {
		return "", "", err
	}
	secretBytes, err := GenerateRandomHex(24)
	if err != nil {
		return "", "", err
	}
	prefix = prefixBytes
	rawKey = fmt.Sprintf("sp_%s_%s", prefix, secretBytes)
	return rawKey, prefix, nil
}
