package repository

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

// TokenStore define todas as operacoes redis do auth service.
type TokenStore interface {
	// -- phantom tokens --
	SetPhantom(ctx context.Context, phantomToken string, jwt string, ttl time.Duration) error
	GetJWT(ctx context.Context, phantomToken string) (string, error)
	Delete(ctx context.Context, phantomToken string) error

	// -- rate limiting (sliding window) --
	// CheckRateLimit verifica se uma chave (ip:endpoint) excedeu o limite.
	// retorna: allowed, remaining, retryAfter, error
	CheckRateLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, int, time.Duration, error)

	// -- revogacao de usuario (reduz janela de exposicao) --
	IsUserRevoked(ctx context.Context, userID string) (bool, error)

	// -- tokens temporarios mfa --
	// SetMFAToken armazena um token temporario mfa (5 min ttl).
	// usado no fluxo de login quando mfa esta ativo.
	SetMFAToken(ctx context.Context, mfaToken string, userID string, ttl time.Duration) error
	GetMFAToken(ctx context.Context, mfaToken string) (string, error)
	DeleteMFAToken(ctx context.Context, mfaToken string) error

	// -- limitacao de tentativas mfa --
	// IncrMFAAttempts incrementa o contador de tentativas mfa falhadas.
	// protege contra tentativa de adivinhar o codigo totp.
	IncrMFAAttempts(ctx context.Context, userID string, window time.Duration) (int64, error)

	// -- bloqueio de conta (por email, independente de ip) --
	// bloqueia a conta apos n falhas consecutivas - protege contra
	// ataques distribuidos que contornam rate-limiting por ip.
	IncrLoginFailure(ctx context.Context, email string, window time.Duration) (int64, error)
	IsAccountLocked(ctx context.Context, email string) (bool, error)
	LockAccount(ctx context.Context, email string, duration time.Duration) error
	ClearLoginFailures(ctx context.Context, email string) error
}

type redisTokenStore struct {
	client *redis.Client
}

func NewRedisTokenStore(addr string) TokenStore {
	opts, err := redis.ParseURL(addr)
	if err != nil {
		log.Fatalf("redis: url invalida: %v", err)
	}

	opts.DialTimeout = 2 * time.Second
	opts.ReadTimeout = 2 * time.Second
	opts.WriteTimeout = 2 * time.Second

	rdb := redis.NewClient(opts)

	// redis e uma dependencia critica - processo nao inicia sem ele
	pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		log.Fatalf("redis indisponivel - verifique AUTH_REDIS_ADDR: %v", err)
	}

	return &redisTokenStore{client: rdb}
}

// -- phantom token --

func (r *redisTokenStore) SetPhantom(ctx context.Context, phantomToken string, jwt string, ttl time.Duration) error {
	return r.client.Set(ctx, "phantom:"+phantomToken, jwt, ttl).Err()
}

func (r *redisTokenStore) GetJWT(ctx context.Context, phantomToken string) (string, error) {
	return r.client.Get(ctx, "phantom:"+phantomToken).Result()
}

func (r *redisTokenStore) Delete(ctx context.Context, phantomToken string) error {
	return r.client.Del(ctx, "phantom:"+phantomToken).Err()
}

// -- rate limiting (sliding window com sorted set) --

func (r *redisTokenStore) CheckRateLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, int, time.Duration, error) {
	now := time.Now()
	nowNano := now.UnixNano()
	windowStart := nowNano - int64(window)

	rlKey := "ratelimit:" + key

	// pipeline: remove entradas expiradas + conta as atuais
	pipe := r.client.Pipeline()
	pipe.ZRemRangeByScore(ctx, rlKey, "0", fmt.Sprintf("%d", windowStart))
	countCmd := pipe.ZCard(ctx, rlKey)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return true, limit, 0, err // fail open
	}

	count := countCmd.Val()

	if count >= int64(limit) {
		// calcula retry-after a partir da entrada mais antiga na janela
		oldest, err := r.client.ZRangeWithScores(ctx, rlKey, 0, 0).Result()
		if err == nil && len(oldest) > 0 {
			oldestTime := time.Unix(0, int64(oldest[0].Score))
			retryAfter := window - now.Sub(oldestTime)
			if retryAfter < 0 {
				retryAfter = time.Second
			}
			return false, 0, retryAfter, nil
		}
		return false, 0, window, nil
	}

	// registra esta requisicao
	pipe2 := r.client.Pipeline()
	member := fmt.Sprintf("%d", nowNano)
	pipe2.ZAdd(ctx, rlKey, redis.Z{Score: float64(nowNano), Member: member})
	pipe2.Expire(ctx, rlKey, window)
	_, err = pipe2.Exec(ctx)

	remaining := int(int64(limit) - count - 1)
	if remaining < 0 {
		remaining = 0
	}

	return true, remaining, 0, err
}

// -- revogacao de usuario --

func (r *redisTokenStore) IsUserRevoked(ctx context.Context, userID string) (bool, error) {
	val, err := r.client.Get(ctx, "user:revoked:"+userID).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return val == "1", nil
}

// -- tokens temporarios mfa --

func (r *redisTokenStore) SetMFAToken(ctx context.Context, mfaToken string, userID string, ttl time.Duration) error {
	return r.client.Set(ctx, "mfa:"+mfaToken, userID, ttl).Err()
}

func (r *redisTokenStore) GetMFAToken(ctx context.Context, mfaToken string) (string, error) {
	return r.client.Get(ctx, "mfa:"+mfaToken).Result()
}

func (r *redisTokenStore) DeleteMFAToken(ctx context.Context, mfaToken string) error {
	return r.client.Del(ctx, "mfa:"+mfaToken).Err()
}

// -- limitacao de tentativas mfa --

func (r *redisTokenStore) IncrMFAAttempts(ctx context.Context, userID string, window time.Duration) (int64, error) {
	key := "mfa:attempts:" + userID
	pipe := r.client.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incrCmd.Val(), nil
}

// -- bloqueio de conta --

func (r *redisTokenStore) IncrLoginFailure(ctx context.Context, email string, window time.Duration) (int64, error) {
	key := "login:failures:" + email
	pipe := r.client.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incrCmd.Val(), nil
}

func (r *redisTokenStore) IsAccountLocked(ctx context.Context, email string) (bool, error) {
	val, err := r.client.Get(ctx, "login:locked:"+email).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return val == "1", nil
}

func (r *redisTokenStore) LockAccount(ctx context.Context, email string, duration time.Duration) error {
	return r.client.Set(ctx, "login:locked:"+email, "1", duration).Err()
}

func (r *redisTokenStore) ClearLoginFailures(ctx context.Context, email string) error {
	return r.client.Del(ctx, "login:failures:"+email).Err()
}
