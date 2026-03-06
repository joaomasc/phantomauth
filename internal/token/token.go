package token

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joaomasc/auth-service/internal/model"
)

// Claims define o payload do jwt (assinado com rs256).
type Claims struct {
	UserID string `json:"user_id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateAccessToken cria um jwt assinado com rs256 (chave privada rsa).
// ttl define a validade do token. issuer identifica o servico (claim "iss").
func GenerateAccessToken(user model.User, privateKey *rsa.PrivateKey, ttl time.Duration, issuer string) (string, error) {
	claims := Claims{
		UserID: user.ID.String(),
		Name:   user.Name,
		Email:  user.Email,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   user.ID.String(),
			Audience:  jwt.ClaimStrings{issuer},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        uuid.NewString(), // jti - previne ataques de replay
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return t.SignedString(privateKey)
}

// ValidateAccessToken valida um jwt usando a chave publica rsa.
// rejeita qualquer token que nao use rs256 (previne ataques de confusao de algoritmo).
func ValidateAccessToken(tokenStr string, publicKey *rsa.PublicKey, issuer string) (*Claims, error) {
	tok, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		// critico: rejeitar qualquer algoritmo que nao seja rs256
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing algorithm: %v", t.Header["alg"])
		}
		return publicKey, nil
	}, jwt.WithIssuer(issuer), jwt.WithAudience(issuer))

	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := tok.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("failed to parse claims")
	}

	return claims, nil
}

func GenerateRefreshToken() string {
	return uuid.NewString()
}
