package service

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/joaomasc/auth-service/internal/audit"
	"github.com/joaomasc/auth-service/internal/model"
	"github.com/joaomasc/auth-service/internal/repository"
	"github.com/joaomasc/auth-service/internal/token"
)

// AuthService implementa a logica central de autenticacao:
// jwt rs256, mfa via totp, phantom token pattern, verificacao de revogacao de usuario.
type AuthService struct {
	userRepo    *repository.UserRepository
	refreshRepo repository.RefreshTokenRepository
	mfaRepo     repository.MFARepository
	tokenStore  repository.TokenStore // Redis

	privateKey       *rsa.PrivateKey
	publicKey        *rsa.PublicKey
	mfaEncryptionKey []byte
	issuer           string

	phantomTTL time.Duration
	refreshTTL time.Duration
}

func NewAuthService(
	userRepo *repository.UserRepository,
	refreshRepo repository.RefreshTokenRepository,
	mfaRepo repository.MFARepository,
	tokenStore repository.TokenStore,
	privateKey *rsa.PrivateKey,
	publicKey *rsa.PublicKey,
	mfaEncryptionKey []byte,
	issuer string,
	phantomTTL time.Duration,
	refreshTTL time.Duration,
) *AuthService {
	return &AuthService{
		userRepo:         userRepo,
		refreshRepo:      refreshRepo,
		mfaRepo:          mfaRepo,
		tokenStore:       tokenStore,
		privateKey:       privateKey,
		publicKey:        publicKey,
		mfaEncryptionKey: mfaEncryptionKey,
		issuer:           issuer,
		phantomTTL:       phantomTTL,
		refreshTTL:       refreshTTL,
	}
}

// -- login --
// se mfa esta ativo, retorna MFARequired=true com um token temporario.
// o frontend deve chamar /mfa/validate com esse token + o codigo totp.

// LoginInfo carrega metadados da requisicao http para auditoria de seguranca.
type LoginInfo struct {
	IP        string
	UserAgent string
}

// limites de bloqueio de conta (por email, independente de ip).
const (
	loginFailureMax    = 10 // bloqueia apos 10 falhas
	loginFailureWindow = 15 * time.Minute
	loginLockDuration  = 30 * time.Minute
)

func (s *AuthService) Login(ctx context.Context, email, password string, info ...LoginInfo) (*LoginResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	var ip, ua string
	if len(info) > 0 {
		ip, ua = info[0].IP, info[0].UserAgent
	}

	// verifica se a conta esta bloqueada
	locked, err := s.tokenStore.IsAccountLocked(ctx, email)
	if err != nil {
		log.Printf("[WARN] erro ao verificar bloqueio para %s: %v", email, err)
	} else if locked {
		audit.Log(audit.Event{
			Event:     audit.EventLoginFailure,
			Email:     email,
			IP:        ip,
			UserAgent: ua,
			Success:   false,
			Reason:    "account_locked",
		})
		return nil, errors.New("conta temporariamente bloqueada")
	}

	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		_ = s.recordLoginFailure(ctx, email, ip, ua, "user_not_found")
		return nil, errors.New("credenciais invalidas")
	}

	if !user.Active {
		_ = s.recordLoginFailure(ctx, email, ip, ua, "user_inactive")
		return nil, errors.New("credenciais invalidas")
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		_ = s.recordLoginFailure(ctx, email, ip, ua, "wrong_password")
		return nil, errors.New("credenciais invalidas")
	}

	// credenciais validas - limpa contador de falhas
	_ = s.tokenStore.ClearLoginFailures(ctx, email)

	// verifica se mfa esta ativo
	dbCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mfa, err := s.mfaRepo.FindByUserID(dbCtx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("erro ao verificar mfa: %w", err)
	}

	if mfa != nil && mfa.Enabled {
		// mfa ativo - gera token temporario e solicita codigo totp
		mfaToken := uuid.NewString()
		err := s.tokenStore.SetMFAToken(dbCtx, mfaToken, user.ID.String(), 5*time.Minute)
		if err != nil {
			return nil, fmt.Errorf("error creating mfa session: %w", err)
		}
		audit.Log(audit.Event{
			Event:     audit.EventLoginMFARequired,
			UserID:    user.ID.String(),
			Email:     email,
			IP:        ip,
			UserAgent: ua,
			Success:   true,
		})
		return &LoginResult{
			MFARequired: true,
			MFAToken:    mfaToken,
		}, nil
	}

	// sem mfa - gera tokens normalmente
	phantomToken, refreshToken, err := s.generateTokens(dbCtx, user)
	if err != nil {
		return nil, err
	}

	audit.Log(audit.Event{
		Event:     audit.EventLoginSuccess,
		UserID:    user.ID.String(),
		Email:     email,
		IP:        ip,
		UserAgent: ua,
		Success:   true,
	})

	return &LoginResult{
		AccessToken:  phantomToken,
		RefreshToken: refreshToken,
	}, nil
}

// recordLoginFailure incrementa o contador de falhas e bloqueia a conta se necessario.
func (s *AuthService) recordLoginFailure(ctx context.Context, email, ip, ua, reason string) error {
	audit.Log(audit.Event{
		Event:     audit.EventLoginFailure,
		Email:     email,
		IP:        ip,
		UserAgent: ua,
		Success:   false,
		Reason:    reason,
	})

	failures, err := s.tokenStore.IncrLoginFailure(ctx, email, loginFailureWindow)
	if err != nil {
		return err
	}

	if failures >= loginFailureMax {
		_ = s.tokenStore.LockAccount(ctx, email, loginLockDuration)
		audit.Log(audit.Event{
			Event:   audit.EventAccountLocked,
			Email:   email,
			IP:      ip,
			Success: false,
			Reason:  fmt.Sprintf("%d consecutive failures", failures),
		})
	}
	return nil
}

// -- introspect --
// valida o phantom token e verifica se o usuario foi revogado.
func (s *AuthService) Introspect(ctx context.Context, phantomToken string) (*token.Claims, error) {
	jwtStr, err := s.tokenStore.GetJWT(ctx, phantomToken)
	if err != nil {
		return nil, errors.New("token invalido ou expirado")
	}

	claims, err := token.ValidateAccessToken(jwtStr, s.publicKey, s.issuer)
	if err != nil {
		return nil, errors.New("token interno corrompido")
	}

	// verifica revogacao de usuario no redis
	revoked, err := s.tokenStore.IsUserRevoked(ctx, claims.UserID)
	if err != nil {
		// fail open apenas em erro de redis
		log.Printf("[WARN] erro ao verificar revogacao do usuario %s: %v", claims.UserID, err)
	} else if revoked {
		_ = s.tokenStore.Delete(ctx, phantomToken)
		return nil, errors.New("utilizador revogado")
	}

	return claims, nil
}

// -- generateTokens --
func (s *AuthService) generateTokens(ctx context.Context, user model.User) (string, string, error) {
	// gera jwt real (rs256)
	jwtToken, err := token.GenerateAccessToken(user, s.privateKey, s.phantomTTL, s.issuer)
	if err != nil {
		return "", "", err
	}

	// phantom token opaco
	phantomToken := uuid.NewString()

	// armazena phantom -> jwt no redis
	err = s.tokenStore.SetPhantom(ctx, phantomToken, jwtToken, s.phantomTTL)
	if err != nil {
		return "", "", err
	}

	// persiste refresh token no db
	refreshToken := token.GenerateRefreshToken()
	rt := &model.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(s.refreshTTL),
		Revoked:   false,
	}
	if err := s.refreshRepo.Save(ctx, rt); err != nil {
		return "", "", fmt.Errorf("falha ao salvar refresh token: %w", err)
	}

	return phantomToken, refreshToken, nil
}

// -- refresh --
func (s *AuthService) Refresh(ctx context.Context, refreshTokenStr string) (string, string, error) {
	dbCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rt, err := s.refreshRepo.FindByToken(dbCtx, refreshTokenStr)
	if err != nil {
		return "", "", errors.New("refresh token invalido")
	}

	// deteccao de reuso - revoga toda a familia de tokens
	if rt.Revoked {
		log.Printf("[SEGURANCA] reuso de refresh token detectado para user_id=%s, revogando todas as sessoes", rt.UserID)
		_ = s.refreshRepo.RevokeAllForUser(dbCtx, rt.UserID)
		audit.Log(audit.Event{
			Event:   audit.EventTokenRefreshReuse,
			UserID:  rt.UserID.String(),
			Success: false,
			Reason:  "refresh_token_reuse_detected",
		})
		return "", "", errors.New("sessao invalida - faca login novamente")
	}

	if rt.ExpiresAt.Before(time.Now()) {
		return "", "", errors.New("sessao expirada - faca login novamente")
	}

	user, err := s.userRepo.FindByID(rt.UserID)
	if err != nil {
		return "", "", errors.New("utilizador nao encontrado")
	}
	if !user.Active {
		return "", "", errors.New("conta desativada")
	}

	// revoga token antigo antes de emitir o novo
	if err := s.refreshRepo.Revoke(dbCtx, refreshTokenStr); err != nil {
		return "", "", fmt.Errorf("falha ao revogar token antigo: %w", err)
	}

	return s.generateTokens(dbCtx, user)
}

// -- register --
func (s *AuthService) Register(ctx context.Context, name, email, password string) (string, string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	name = strings.TrimSpace(name)

	// verificacao de complexidade da senha (owasp)
	if err := validatePasswordStrength(password); err != nil {
		return "", "", err
	}

	// verifica se a senha foi comprometida (nist sp 800-63b)
	pwnedCount, err := checkPasswordPwned(password)
	if err != nil {
		log.Printf("[WARN] verificacao hibp falhou: %v", err)
	}
	if pwnedCount > 0 {
		audit.Log(audit.Event{Event: audit.EventRegisterFailure, Email: email, Success: false, Reason: "password_pwned"})
		return "", "", fmt.Errorf("esta senha apareceu em %d vazamentos de dados conhecidos - escolha outra", pwnedCount)
	}

	_, err = s.userRepo.FindByEmail(email)
	if err == nil {
		// nao revela se email existe - previne enumeracao de usuarios
		audit.Log(audit.Event{Event: audit.EventRegisterFailure, Email: email, Success: false, Reason: "email_already_exists"})
		return "", "", errors.New("nao foi possivel criar a conta com estes dados")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		log.Printf("[register] falha ao fazer hash da senha: %v", err)
		return "", "", fmt.Errorf("erro ao processar senha: %w", err)
	}

	dbCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	user, err := s.userRepo.CreateUser(dbCtx, name, email, string(hash), "admin")
	if err != nil {
		log.Printf("[register] falha ao criar usuario (email=%q): %v", email, err)
		return "", "", fmt.Errorf("falha ao criar conta: %w", err)
	}

	accessToken, refreshToken, err := s.generateTokens(dbCtx, user)
	if err != nil {
		log.Printf("[register] falha ao gerar tokens para %q: %v", user.Email, err)
		return "", "", fmt.Errorf("conta criada mas falha ao gerar sessao: %w", err)
	}

	audit.Log(audit.Event{Event: audit.EventRegister, UserID: user.ID.String(), Email: email, Success: true})

	return accessToken, refreshToken, nil
}

// -- logout --
// destroi phantom token no redis e revoga refresh token no postgres.
func (s *AuthService) Logout(ctx context.Context, phantomToken string, refreshToken string) error {
	dbCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// remove phantom token do redis
	if phantomToken != "" {
		_ = s.tokenStore.Delete(dbCtx, phantomToken)
	}

	// revoga refresh token no postgres
	if refreshToken != "" {
		_ = s.refreshRepo.Revoke(dbCtx, refreshToken)
	}

	audit.Log(audit.Event{Event: audit.EventLogout, Success: true})

	return nil
}

// -- mfa (totp) --

// MFASetup gera um novo segredo totp para o usuario.
// o segredo e criptografado com aes-256-gcm antes de armazenar no db.
// retorna segredo base32, url otpauth e qr code como base64 png.
func (s *AuthService) MFASetup(ctx context.Context, userID string) (string, string, string, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return "", "", "", errors.New("user_id invalido")
	}

	user, err := s.userRepo.FindByID(uid)
	if err != nil {
		return "", "", "", errors.New("utilizador nao encontrado")
	}

	// gera novo segredo totp
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: user.Email,
	})
	if err != nil {
		return "", "", "", fmt.Errorf("falha ao gerar segredo totp: %w", err)
	}

	// gera qr code como base64 png
	qrImg, err := key.Image(200, 200)
	if err != nil {
		return "", "", "", fmt.Errorf("falha ao gerar qr code: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, qrImg); err != nil {
		return "", "", "", fmt.Errorf("falha ao codificar qr code: %w", err)
	}
	qrBase64 := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

	// criptografa segredo antes de armazenar no db
	encryptedSecret, err := encryptTOTPSecret(key.Secret(), s.mfaEncryptionKey)
	if err != nil {
		return "", "", "", fmt.Errorf("falha ao criptografar segredo totp: %w", err)
	}

	dbCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// salva no db (enabled=false ate o usuario confirmar com o primeiro codigo)
	err = s.mfaRepo.Upsert(dbCtx, uid, encryptedSecret, false)
	if err != nil {
		return "", "", "", fmt.Errorf("falha ao salvar mfa: %w", err)
	}

	return key.Secret(), key.URL(), qrBase64, nil
}

// MFAVerifySetup valida o primeiro codigo totp e ativa o mfa.
func (s *AuthService) MFAVerifySetup(ctx context.Context, userID string, code string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return errors.New("user_id invalido")
	}

	dbCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mfa, err := s.mfaRepo.FindByUserID(dbCtx, uid)
	if err != nil {
		return fmt.Errorf("falha ao buscar mfa: %w", err)
	}
	if mfa == nil {
		return errors.New("mfa nao configurado - use /mfa/setup primeiro")
	}

	// descriptografa segredo para validar o codigo
	secret, err := decryptTOTPSecret(mfa.Secret, s.mfaEncryptionKey)
	if err != nil {
		return fmt.Errorf("falha ao descriptografar segredo totp: %w", err)
	}

	if !totp.Validate(code, secret) {
		return errors.New("codigo totp invalido")
	}

	audit.Log(audit.Event{Event: audit.EventMFAEnabled, UserID: userID, Success: true})
	return s.mfaRepo.Enable(dbCtx, uid)
}

// MFAValidateLogin valida o codigo totp durante o fluxo de login.
func (s *AuthService) MFAValidateLogin(ctx context.Context, mfaToken string, code string) (string, string, error) {
	userIDStr, err := s.tokenStore.GetMFAToken(ctx, mfaToken)
	if err != nil {
		return "", "", errors.New("sessao mfa expirada ou invalida - faca login novamente")
	}

	uid, err := uuid.Parse(userIDStr)
	if err != nil {
		return "", "", errors.New("sessao mfa corrompida")
	}

	// verifica limite de tentativas (max 5 em 5 minutos)
	attempts, err := s.tokenStore.IncrMFAAttempts(ctx, userIDStr, 5*time.Minute)
	if err != nil {
		log.Printf("[WARN] falha ao incrementar tentativas mfa: %v", err)
	} else if attempts > 5 {
		_ = s.tokenStore.DeleteMFAToken(ctx, mfaToken)
		return "", "", errors.New("muitas tentativas mfa - faca login novamente")
	}

	// busca e descriptografa segredo totp
	dbCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mfa, err := s.mfaRepo.FindByUserID(dbCtx, uid)
	if err != nil || mfa == nil {
		return "", "", errors.New("mfa nao configurado")
	}

	secret, err := decryptTOTPSecret(mfa.Secret, s.mfaEncryptionKey)
	if err != nil {
		return "", "", errors.New("erro interno mfa")
	}

	if !totp.Validate(code, secret) {
		audit.Log(audit.Event{Event: audit.EventMFAFailure, UserID: userIDStr, Success: false, Reason: "invalid_totp"})
		return "", "", errors.New("codigo totp invalido")
	}

	// codigo valido - deleta token mfa e gera tokens reais
	_ = s.tokenStore.DeleteMFAToken(ctx, mfaToken)
	audit.Log(audit.Event{Event: audit.EventMFASuccess, UserID: userIDStr, Success: true})

	user, err := s.userRepo.FindByID(uid)
	if err != nil {
		return "", "", errors.New("utilizador nao encontrado")
	}
	if !user.Active {
		return "", "", errors.New("conta desativada")
	}

	return s.generateTokens(dbCtx, user)
}

// MFADisable desativa o mfa apos validar o codigo totp (requer confirmacao).
func (s *AuthService) MFADisable(ctx context.Context, userID string, code string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return errors.New("user_id invalido")
	}

	dbCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mfa, err := s.mfaRepo.FindByUserID(dbCtx, uid)
	if err != nil || mfa == nil {
		return errors.New("mfa nao esta configurado")
	}
	if !mfa.Enabled {
		return errors.New("mfa ja esta desativado")
	}

	secret, err := decryptTOTPSecret(mfa.Secret, s.mfaEncryptionKey)
	if err != nil {
		return errors.New("erro interno mfa")
	}

	if !totp.Validate(code, secret) {
		return errors.New("codigo totp invalido")
	}

	audit.Log(audit.Event{Event: audit.EventMFADisabled, UserID: userID, Success: true})
	return s.mfaRepo.Delete(dbCtx, uid)
}

// MFAStatus retorna se o mfa esta ativo para o usuario.
func (s *AuthService) MFAStatus(ctx context.Context, userID string) (bool, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return false, errors.New("user_id invalido")
	}

	dbCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mfa, err := s.mfaRepo.FindByUserID(dbCtx, uid)
	if err != nil {
		return false, err
	}
	if mfa == nil {
		return false, nil
	}
	return mfa.Enabled, nil
}
