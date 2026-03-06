package service

import (
	"context"

	"github.com/joaomasc/auth-service/internal/token"
)

// LoginResult armazena o resultado de uma tentativa de login.
// se mfa esta ativo, tokens ficam vazios e mfa_token e definido.
type LoginResult struct {
	AccessToken  string // phantom token (vazio se mfa pendente)
	RefreshToken string // refresh token (vazio se mfa pendente)
	MFARequired  bool   // true = precisa do codigo totp
	MFAToken     string // token temporario para validacao mfa (5min ttl)
}

// AuthServiceInterface define o contrato que tanto *AuthService quanto
// *TimedAuthService implementam. o controller depende desta interface.
type AuthServiceInterface interface {
	// -- auth core --
	Login(ctx context.Context, email, password string, info ...LoginInfo) (*LoginResult, error)
	Introspect(ctx context.Context, phantomToken string) (*token.Claims, error)
	Refresh(ctx context.Context, refreshToken string) (newPhantomToken string, newRefreshToken string, err error)
	Register(ctx context.Context, name, email, password string) (phantomToken string, refreshToken string, err error)
	Logout(ctx context.Context, phantomToken string, refreshToken string) error

	// -- mfa (totp) --
	MFASetup(ctx context.Context, userID string) (secret string, otpauthURL string, qrCode string, err error)
	MFAVerifySetup(ctx context.Context, userID string, code string) error
	MFAValidateLogin(ctx context.Context, mfaToken string, code string) (accessToken string, refreshToken string, err error)
	MFADisable(ctx context.Context, userID string, code string) error
	MFAStatus(ctx context.Context, userID string) (enabled bool, err error)
}
