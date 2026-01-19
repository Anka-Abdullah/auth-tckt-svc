package security

import (
	"time"

	"auth-svc-ticketing/internal/core/ports"

	"github.com/golang-jwt/jwt/v5"
)

type jwtManager struct {
	secretKey       string
	accessDuration  time.Duration
	refreshDuration time.Duration
}

// NewJWTManager constructor
func NewJWTManager(secretKey string, accessDuration, refreshDuration time.Duration) ports.JWTManager {
	return &jwtManager{
		secretKey:       secretKey,
		accessDuration:  accessDuration,
		refreshDuration: refreshDuration,
	}
}

func (m *jwtManager) Generate(userID, email string, roles []string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"roles":   roles,
		"exp":     time.Now().Add(m.accessDuration).Unix(),
		"iat":     time.Now().Unix(),
		"type":    "access",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.secretKey))
}

func (m *jwtManager) GenerateRefreshToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(m.refreshDuration).Unix(),
		"iat":     time.Now().Unix(),
		"type":    "refresh",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.secretKey))
}

func (m *jwtManager) Verify(tokenString string) (*ports.JWTClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(m.secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}

	// Check token type
	if tokenType, ok := claims["type"].(string); !ok || tokenType != "access" {
		return nil, jwt.ErrTokenInvalidClaims
	}

	// Extract claims
	userID, ok := claims["user_id"].(string)
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}

	email, _ := claims["email"].(string)

	var roles []string
	if rolesInterface, ok := claims["roles"].([]interface{}); ok {
		for _, role := range rolesInterface {
			if roleStr, ok := role.(string); ok {
				roles = append(roles, roleStr)
			}
		}
	}

	return &ports.JWTClaims{
		UserID: userID,
		Email:  email,
		Roles:  roles,
	}, nil
}

func (m *jwtManager) VerifyRefreshToken(tokenString string) (*ports.JWTClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(m.secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}

	// Check token type
	if tokenType, ok := claims["type"].(string); !ok || tokenType != "refresh" {
		return nil, jwt.ErrTokenInvalidClaims
	}

	// Extract user ID
	userID, ok := claims["user_id"].(string)
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}

	return &ports.JWTClaims{
		UserID: userID,
	}, nil
}
