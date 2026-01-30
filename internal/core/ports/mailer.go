package ports

type Mailer interface {
	SendOTPEmail(email, otp string) error
}
