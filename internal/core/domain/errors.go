package domain

import "errors"

var (
	ErrEmailExists        = errors.New("email already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidToken       = errors.New("invalid token")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired       = errors.New("token expired")
	ErrUserNotVerified    = errors.New("user not verified")
	ErrUserInactive       = errors.New("user is inactive")
	ErrWeakPassword       = errors.New("password is too weak")
)
