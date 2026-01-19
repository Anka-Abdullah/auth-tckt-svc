package ports

type JWTManager interface {
	Generate(userID, email string, roles []string) (string, error)
	Verify(tokenString string) (*JWTClaims, error)
	GenerateRefreshToken(userID string) (string, error)
	VerifyRefreshToken(tokenString string) (*JWTClaims, error)
}

type JWTClaims struct {
	UserID string   `json:"user_id"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
}
