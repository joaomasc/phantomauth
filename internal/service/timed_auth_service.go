package service

// TimedAuthService envolve o AuthService e loga o tempo de cada operacao.
// nao altera nenhuma logica de negocio.

import (
	"context"
	"log"
	"time"

	"github.com/joaomasc/auth-service/internal/token"
)

type TimedAuthService struct {
	inner *AuthService
}

// NewTimedAuthService cria o wrapper de timing em volta do AuthService real.
func NewTimedAuthService(inner *AuthService) *TimedAuthService {
	return &TimedAuthService{inner: inner}
}

func (t *TimedAuthService) Login(ctx context.Context, email, password string, info ...LoginInfo) (*LoginResult, error) {
	t1 := time.Now()
	result, err := t.inner.Login(ctx, email, password, info...)
	d := time.Since(t1)

	status := "OK"
	if err != nil {
		status = "FAILED"
	} else if result.MFARequired {
		status = "MFA_REQUIRED"
	}

	log.Printf("[TIMING][login] total=%-10s status=%s email=%s", d, status, email)
	return result, err
}

func (t *TimedAuthService) Introspect(ctx context.Context, phantomToken string) (*token.Claims, error) {
	t1 := time.Now()
	claims, err := t.inner.Introspect(ctx, phantomToken)
	d := time.Since(t1)

	status := "ok"
	if d > 500*time.Millisecond {
		status = "slow=redis"
	}
	log.Printf("[TIMING][validate] [redis.getjwt+revcheck]=%-10s %s", d, status)

	return claims, err
}

func (t *TimedAuthService) Refresh(ctx context.Context, refreshToken string) (string, string, error) {
	t1 := time.Now()
	a, b, err := t.inner.Refresh(ctx, refreshToken)
	log.Printf("[TIMING][refresh] total=%s", time.Since(t1))
	return a, b, err
}

func (t *TimedAuthService) Register(ctx context.Context, name, email, password string) (string, string, error) {
	t1 := time.Now()
	a, b, err := t.inner.Register(ctx, name, email, password)
	log.Printf("[TIMING][register] total=%s email=%s", time.Since(t1), email)
	return a, b, err
}

func (t *TimedAuthService) Logout(ctx context.Context, phantomToken string, refreshToken string) error {
	t1 := time.Now()
	err := t.inner.Logout(ctx, phantomToken, refreshToken)
	log.Printf("[TIMING][logout] total=%s", time.Since(t1))
	return err
}

// -- delegados mfa --

func (t *TimedAuthService) MFASetup(ctx context.Context, userID string) (string, string, string, error) {
	t1 := time.Now()
	s, u, q, err := t.inner.MFASetup(ctx, userID)
	log.Printf("[TIMING][mfa/setup] total=%s user=%s", time.Since(t1), userID)
	return s, u, q, err
}

func (t *TimedAuthService) MFAVerifySetup(ctx context.Context, userID string, code string) error {
	t1 := time.Now()
	err := t.inner.MFAVerifySetup(ctx, userID, code)
	log.Printf("[TIMING][mfa/verify-setup] total=%s user=%s", time.Since(t1), userID)
	return err
}

func (t *TimedAuthService) MFAValidateLogin(ctx context.Context, mfaToken string, code string) (string, string, error) {
	t1 := time.Now()
	a, b, err := t.inner.MFAValidateLogin(ctx, mfaToken, code)
	log.Printf("[TIMING][mfa/validate] total=%s", time.Since(t1))
	return a, b, err
}

func (t *TimedAuthService) MFADisable(ctx context.Context, userID string, code string) error {
	t1 := time.Now()
	err := t.inner.MFADisable(ctx, userID, code)
	log.Printf("[TIMING][mfa/disable] total=%s user=%s", time.Since(t1), userID)
	return err
}

func (t *TimedAuthService) MFAStatus(ctx context.Context, userID string) (bool, error) {
	t1 := time.Now()
	ok, err := t.inner.MFAStatus(ctx, userID)
	log.Printf("[TIMING][mfa/status] total=%s user=%s", time.Since(t1), userID)
	return ok, err
}
