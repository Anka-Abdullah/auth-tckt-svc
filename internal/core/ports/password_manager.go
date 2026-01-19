package ports

type PasswordManager interface {
	HashPassword(password string) (string, error)
	CheckPasswordHash(password, hash string) bool
	GenerateRandomPassword(length int) (string, error)
}
