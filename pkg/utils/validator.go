package utils

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

type CustomValidator struct {
	validator *validator.Validate
}

func NewCustomValidator() *CustomValidator {
	v := validator.New()

	// Register custom validations
	v.RegisterValidation("password", validatePassword)
	v.RegisterValidation("phone", validatePhone)
	v.RegisterValidation("username", validateUsername)
	v.RegisterValidation("alphanumspace", validateAlphaNumSpace)

	// Register tag name function
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	return &CustomValidator{validator: v}
}

func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.validator.Struct(i); err != nil {
		return translateValidationError(err)
	}
	return nil
}

// Custom validation functions
func validatePassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	if len(password) < 8 {
		return false
	}

	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`\d`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password)

	return hasUpper && hasLower && hasDigit && hasSpecial
}

func validatePhone(fl validator.FieldLevel) bool {
	phone := fl.Field().String()
	phoneRegex := `^(?:\+62|62|0)(?:\d{8,15})$`
	matched, _ := regexp.MatchString(phoneRegex, phone)
	return matched
}

func validateUsername(fl validator.FieldLevel) bool {
	username := fl.Field().String()
	usernameRegex := `^[a-zA-Z0-9_]{3,20}$`
	matched, _ := regexp.MatchString(usernameRegex, username)
	return matched
}

func validateAlphaNumSpace(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	alphaNumSpaceRegex := `^[a-zA-Z0-9\s]+$`
	matched, _ := regexp.MatchString(alphaNumSpaceRegex, value)
	return matched
}

func translateValidationError(err error) error {
	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		var errorMessages []string

		for _, e := range validationErrors {
			var message string

			switch e.Tag() {
			case "required":
				message = fmt.Sprintf("%s is required", e.Field())
			case "email":
				message = fmt.Sprintf("%s must be a valid email", e.Field())
			case "min":
				message = fmt.Sprintf("%s must be at least %s characters", e.Field(), e.Param())
			case "max":
				message = fmt.Sprintf("%s must be at most %s characters", e.Field(), e.Param())
			case "password":
				message = fmt.Sprintf("%s must contain at least 8 characters with uppercase, lowercase, number, and special character", e.Field())
			case "phone":
				message = fmt.Sprintf("%s must be a valid phone number", e.Field())
			case "username":
				message = fmt.Sprintf("%s must be 3-20 characters with letters, numbers, and underscores only", e.Field())
			case "alphanumspace":
				message = fmt.Sprintf("%s must contain only letters, numbers, and spaces", e.Field())
			case "eqfield":
				message = fmt.Sprintf("%s must match %s", e.Field(), e.Param())
			default:
				message = fmt.Sprintf("%s is invalid", e.Field())
			}

			errorMessages = append(errorMessages, message)
		}

		return fmt.Errorf(strings.Join(errorMessages, "; "))
	}

	return err
}
