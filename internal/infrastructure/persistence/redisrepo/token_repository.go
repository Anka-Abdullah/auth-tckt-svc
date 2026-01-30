package redisrepo

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
)

type TokenRepository struct {
	client *redis.Client
	ctx    context.Context
}

func NewTokenRepository(client *redis.Client) *TokenRepository {
	return &TokenRepository{
		client: client,
		ctx:    context.Background(),
	}
}

func (r *TokenRepository) SetToken(key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(r.ctx, key, value, expiration).Err()
}

func (r *TokenRepository) GetToken(key string) (string, error) {
	val, err := r.client.Get(r.ctx, key).Result()
	if err == redis.Nil {
		return "", nil
	}
	return val, err
}

func (r *TokenRepository) DeleteToken(key string) error {
	return r.client.Del(r.ctx, key).Err()
}

// Additional methods for OTP
func (r *TokenRepository) SetOTP(email, otp string, expiration time.Duration) error {
	key := "otp:" + email
	return r.client.Set(r.ctx, key, otp, expiration).Err()
}

func (r *TokenRepository) GetOTP(email string) (string, error) {
	key := "otp:" + email
	val, err := r.client.Get(r.ctx, key).Result()
	if err == redis.Nil {
		return "", nil
	}
	return val, err
}

func (r *TokenRepository) DeleteOTP(email string) error {
	key := "otp:" + email
	return r.client.Del(r.ctx, key).Err()
}

// Check if token exists
func (r *TokenRepository) Exists(key string) (bool, error) {
	val, err := r.client.Exists(r.ctx, key).Result()
	return val > 0, err
}
