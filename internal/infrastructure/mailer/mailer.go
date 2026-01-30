// FILE: ./internal/infrastructure/mailer/mailer.go
package mailer

import (
	"bytes"
	"fmt"
	"net/smtp"
	"time"

	"auth-svc-ticketing/pkg/logger"
)

type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

type Mailer struct {
	config *Config
	logger *logger.Logger
}

func NewMailer(config *Config, logger *logger.Logger) *Mailer {
	return &Mailer{
		config: config,
		logger: logger,
	}
}

// SendOTPEmail implements ports.Mailer interface
func (m *Mailer) SendOTPEmail(email, otp string) error {
	return m.SendOTPEmailWithPurpose(email, otp, "verify")
}

// SendOTPEmailWithPurpose - Versi dengan purpose yang spesifik
func (m *Mailer) SendOTPEmailWithPurpose(email, otp, purpose string) error {
	var subject, title, description string

	switch purpose {
	case "register":
		subject = "Verification OTP for Registration"
		title = "Welcome! Verify Your Registration"
		description = "Thank you for registering. Use the OTP below to complete your registration."
	case "login":
		subject = "Login OTP"
		title = "Login Verification"
		description = "Use the OTP below to login to your account."
	case "reset_password":
		subject = "Password Reset OTP"
		title = "Reset Your Password"
		description = "You requested to reset your password. Use the OTP below to continue."
	case "verify":
		subject = "Email Verification OTP"
		title = "Verify Your Email"
		description = "Please verify your email address using the OTP below."
	default:
		subject = "Your OTP Code"
		title = "Your Verification Code"
		description = "Use the OTP below to complete your action."
	}

	body := m.generateOTPEmailTemplate(title, description, otp, purpose)

	if m.config == nil || m.config.Host == "" {
		m.logger.Info("Dummy OTP email",
			"to", email,
			"purpose", purpose,
			"otp", otp,
		)
		return nil
	}

	return m.sendEmail(email, subject, body)
}

func (m *Mailer) generateOTPEmailTemplate(title, description, otp, purpose string) string {
	currentYear := time.Now().Year()
	expiryMinutes := 5

	// Tentukan page berdasarkan purpose
	var page string
	switch purpose {
	case "register":
		page = "registration"
	case "login":
		page = "login"
	case "reset_password":
		page = "password reset"
	default:
		page = "verification"
	}

	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: #f9fafb;
            margin: 0;
            padding: 0;
            line-height: 1.6;
            color: #374151;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            padding: 40px 30px;
            text-align: center;
            color: white;
        }
        .header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 600;
        }
        .content {
            padding: 40px 30px;
        }
        .otp-container {
            background-color: #f3f4f6;
            border-radius: 8px;
            padding: 30px;
            text-align: center;
            margin: 30px 0;
            border: 2px dashed #d1d5db;
        }
        .otp-code {
            font-size: 42px;
            font-weight: 700;
            letter-spacing: 8px;
            color: #1f2937;
            margin: 0;
            font-family: 'Courier New', monospace;
        }
        .expiry {
            color: #ef4444;
            font-weight: 600;
            margin: 20px 0;
            font-size: 16px;
        }
        .instructions {
            background-color: #f8fafc;
            border-radius: 8px;
            padding: 20px;
            margin: 25px 0;
            border-left: 4px solid #3b82f6;
        }
        .footer {
            text-align: center;
            padding: 25px;
            color: #6b7280;
            font-size: 14px;
            border-top: 1px solid #e5e7eb;
            background-color: #f9fafb;
        }
        .logo {
            font-size: 24px;
            font-weight: 700;
            color: white;
            margin-bottom: 10px;
        }
        @media (max-width: 600px) {
            .container {
                margin: 10px;
                border-radius: 8px;
            }
            .otp-code {
                font-size: 32px;
                letter-spacing: 6px;
            }
            .content {
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🔐 Auth Service</div>
            <h1>%s</h1>
        </div>
        
        <div class="content">
            <p style="font-size: 16px; margin-bottom: 20px;">%s</p>
            
            <div class="otp-container">
                <p style="margin: 0 0 15px 0; color: #4b5563; font-size: 15px;">Enter this code where prompted:</p>
                <p class="otp-code">%s</p>
                <p style="margin: 15px 0 0 0; color: #6b7280; font-size: 14px;">Valid for one-time use only</p>
            </div>
            
            <div class="expiry">
                ⏰ Expires in %d minutes
            </div>
            
            <div class="instructions">
                <strong>How to use:</strong>
                <ol style="margin: 10px 0 0 20px; padding: 0;">
                    <li>Go back to the %s page</li>
                    <li>Enter the 6-digit code shown above</li>
                    <li>Click "Verify" or "Submit" to continue</li>
                </ol>
            </div>
            
            <div style="background-color: #fef2f2; border-radius: 8px; padding: 16px; margin: 25px 0;">
                <strong style="color: #dc2626;">⚠️ Security Notice:</strong>
                <ul style="margin: 8px 0 0 0; padding-left: 20px;">
                    <li>Never share this code with anyone</li>
                    <li>Our team will never ask for your OTP</li>
                    <li>This code is only valid for %d minutes</li>
                    <li>If you didn't request this, please ignore this email</li>
                </ul>
            </div>
        </div>
        
        <div class="footer">
            <p style="margin: 0 0 8px 0;">
                <strong>Auth Service</strong><br>
                Secure Authentication System
            </p>
            <p style="margin: 0; font-size: 13px; color: #9ca3af;">
                This is an automated message. Please do not reply to this email.<br>
                © %d Auth Service. All rights reserved.
            </p>
        </div>
    </div>
</body>
</html>
`, title, title, description, otp, expiryMinutes, page, expiryMinutes, currentYear)
}

func (m *Mailer) sendEmail(to, subject, body string) error {
	headers := make(map[string]string)
	headers["From"] = m.config.From
	headers["To"] = to
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=\"UTF-8\""

	var message bytes.Buffer
	for key, value := range headers {
		message.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}
	message.WriteString("\r\n")
	message.WriteString(body)

	auth := smtp.PlainAuth("", m.config.Username, m.config.Password, m.config.Host)
	addr := fmt.Sprintf("%s:%d", m.config.Host, m.config.Port)

	err := smtp.SendMail(addr, auth, m.config.From, []string{to}, message.Bytes())
	if err != nil {
		m.logger.Error("Failed to send OTP email", err,
			"to", to,
			"subject", subject,
		)
		return err
	}

	m.logger.Info("OTP email sent successfully",
		"to", to,
		"subject", subject,
	)
	return nil
}
