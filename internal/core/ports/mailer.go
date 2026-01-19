package ports

import "auth-svc-ticketing/internal/core/domain"

type Mailer interface {
	SendVerificationEmail(user *domain.User, token string) error
	SendPasswordResetEmail(email, token string) error
	SendWelcomeEmail(user *domain.User) error
}
