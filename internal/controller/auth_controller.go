package controller

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/joaomasc/auth-service/internal/service"
)

// -- config de cookies --
const (
	cookiePath     = "/"
	cookieMaxAge5m = 300    // 5 min (phantom token ttl)
	cookieMaxAge7d = 604800 // 7 days (refresh token ttl)
)

// cookieNames retorna os nomes dos cookies.
// em producao (secure=true), usa prefixo __Host- que forca secure, path=/, sem dominio.
func cookieNames(secure bool) (phantom string, refresh string) {
	if secure {
		return "__Host-phantom_token", "__Host-refresh_token"
	}
	return "phantom_token", "refresh_token"
}

// setTokenCookies define cookies httponly com tokens de acesso e refresh.
func (ac *AuthController) setTokenCookies(ctx *gin.Context, accessToken, refreshToken string) {
	// phantom token - curta duracao, httponly, samesite strict
	ctx.SetSameSite(http.SameSiteStrictMode)
	ctx.SetCookie(ac.phantomName, accessToken, cookieMaxAge5m, cookiePath, "", ac.cookieSecure, true)

	// refresh token - longa duracao, httponly, samesite lax (para redirects oauth)
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie(ac.refreshName, refreshToken, cookieMaxAge7d, cookiePath, "", ac.cookieSecure, true)
}

// clearTokenCookies remove cookies de autenticacao.
func (ac *AuthController) clearTokenCookies(ctx *gin.Context) {
	ctx.SetSameSite(http.SameSiteStrictMode)
	ctx.SetCookie(ac.phantomName, "", -1, cookiePath, "", ac.cookieSecure, true)
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie(ac.refreshName, "", -1, cookiePath, "", ac.cookieSecure, true)
}

// extractToken le phantom token do cookie primeiro, depois do header authorization.
func (ac *AuthController) extractToken(ctx *gin.Context) string {
	if token, err := ctx.Cookie(ac.phantomName); err == nil && token != "" {
		return token
	}

	authHeader := ctx.GetHeader("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	return ""
}

// extractRefreshToken le o refresh token do cookie.
func (ac *AuthController) extractRefreshToken(ctx *gin.Context) string {
	if token, err := ctx.Cookie(ac.refreshName); err == nil && token != "" {
		return token
	}
	return ""
}

type AuthController struct {
	authService  service.AuthServiceInterface
	cookieSecure bool
	phantomName  string
	refreshName  string
}

func NewAuthController(authService service.AuthServiceInterface, cookieSecure bool) *AuthController {
	p, r := cookieNames(cookieSecure)
	return &AuthController{
		authService:  authService,
		cookieSecure: cookieSecure,
		phantomName:  p,
		refreshName:  r,
	}
}

// Login godoc
// @Summary      login do usuario
// @Description  autentica com email e senha. se mfa estiver ativo, retorna mfa_token.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      loginRequest  true  "credenciais de login"
// @Success      200   {object}  loginResponse
// @Failure      400   {object}  errorResponse
// @Failure      401   {object}  errorResponse
// @Router       /login [post]
func (c *AuthController) Login(ctx *gin.Context) {
	var req loginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "requisicao invalida"})
		return
	}

	result, err := c.authService.Login(ctx, req.Email, req.Password, service.LoginInfo{
		IP:        ctx.ClientIP(),
		UserAgent: ctx.GetHeader("User-Agent"),
	})
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if result.MFARequired {
		ctx.JSON(http.StatusOK, gin.H{
			"mfa_required": true,
			"mfa_token":    result.MFAToken,
			"message":      "codigo totp necessario",
		})
		return
	}

	c.setTokenCookies(ctx, result.AccessToken, result.RefreshToken)

	ctx.JSON(http.StatusOK, gin.H{
		"message": "login efetuado com sucesso",
	})
}

// Validate godoc
// @Summary      validar token (interno)
// @Description  valida um phantom token e retorna as claims do usuario. usado internamente por servicos dependentes.
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  validateResponse
// @Failure      401  {object}  errorResponse
// @Router       /validate [post]
func (c *AuthController) Validate(ctx *gin.Context) {
	tokenString := c.extractToken(ctx)
	if tokenString == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"valid": false})
		return
	}

	claims, err := c.authService.Introspect(ctx, tokenString)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"valid": false})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"valid":   true,
		"user_id": claims.UserID,
		"name":    claims.Name,
		"email":   claims.Email,
		"role":    claims.Role,
	})
}

// refreshRequest payload para renovacao de token.
type refreshRequest struct {
	RefreshToken string `json:"refresh_token" example:"uuid-do-refresh-token"`
}

// Refresh godoc
//
//	@Summary      renovar token de acesso
//	@Description  troca o refresh_token por um novo par access_token + refresh_token. o refresh_token antigo e revogado (rotacao).
//	@Tags         auth
//	@Accept       json
//	@Produce      json
//	@Param        body  body      refreshRequest  true  "refresh token"
//	@Success      200   {object}  loginResponse
//	@Failure      400   {object}  errorResponse
//	@Failure      401   {object}  errorResponse
//	@Router       /refresh [post]
func (c *AuthController) Refresh(ctx *gin.Context) {
	// tenta cookie primeiro, depois body
	refreshTok := c.extractRefreshToken(ctx)

	if refreshTok == "" {
		// fallback: le do body (compat api gateway)
		var req refreshRequest
		if err := ctx.ShouldBindJSON(&req); err == nil && req.RefreshToken != "" {
			refreshTok = req.RefreshToken
		}
	}

	if refreshTok == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "refresh_token e obrigatorio"})
		return
	}

	access, refresh, err := c.authService.Refresh(ctx.Request.Context(), refreshTok)
	if err != nil {
		c.clearTokenCookies(ctx)
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.setTokenCookies(ctx, access, refresh)

	ctx.JSON(http.StatusOK, gin.H{
		"message": "token renovado com sucesso",
	})
}

// --- logout ---

// logoutRequest
type logoutRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Logout destroi a sessao do usuario.
// @Summary      logout
// @Description  revoga o phantom token (redis) e o refresh token (db), destruindo a sessao.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      logoutRequest  true  "tokens a revogar"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  errorResponse
// @Router       /logout [post]
func (c *AuthController) Logout(ctx *gin.Context) {
	// le tokens dos cookies ou body
	accessTok := c.extractToken(ctx)
	refreshTok := c.extractRefreshToken(ctx)

	// fallback: le do body (compat)
	if accessTok == "" || refreshTok == "" {
		var req logoutRequest
		if err := ctx.ShouldBindJSON(&req); err == nil {
			if accessTok == "" {
				accessTok = req.AccessToken
			}
			if refreshTok == "" {
				refreshTok = req.RefreshToken
			}
		}
	}

	if accessTok == "" && refreshTok == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "nenhum token encontrado"})
		return
	}

	if err := c.authService.Logout(ctx.Request.Context(), accessTok, refreshTok); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// limpa cookies
	c.clearTokenCookies(ctx)

	ctx.JSON(http.StatusOK, gin.H{
		"message": "sessao encerrada com sucesso",
	})
}

// --- endpoints mfa ---

// MFASetup gera um novo segredo totp para o usuario autenticado.
// @Summary      configurar mfa (totp)
// @Description  gera um segredo totp para o google authenticator. mfa so e ativado apos verificar o primeiro codigo em /mfa/verify-setup.
// @Tags         mfa
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  mfaSetupResponse
// @Failure      401  {object}  errorResponse
// @Router       /mfa/setup [post]
func (c *AuthController) MFASetup(ctx *gin.Context) {
	userID := ctx.GetString("user_id")
	if userID == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "token obrigatorio"})
		return
	}

	secret, otpauthURL, qrCode, err := c.authService.MFASetup(ctx.Request.Context(), userID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"secret":      secret,
		"otpauth_url": otpauthURL,
		"qr_code":     qrCode,
		"message":     "escaneie o qr code no google authenticator e insira o codigo em /mfa/verify-setup para ativar.",
	})
}

// MFAVerifySetup confirma o primeiro codigo totp e ativa o mfa.
// @Summary      verificar setup do mfa
// @Description  valida o primeiro codigo totp e ativa o mfa permanentemente para o usuario.
// @Tags         mfa
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      mfaCodeRequest  true  "codigo totp"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  errorResponse
// @Failure      401   {object}  errorResponse
// @Router       /mfa/verify-setup [post]
func (c *AuthController) MFAVerifySetup(ctx *gin.Context) {
	userID := ctx.GetString("user_id")
	if userID == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "token obrigatorio"})
		return
	}

	var req mfaCodeRequest
	if err := ctx.ShouldBindJSON(&req); err != nil || req.Code == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "codigo totp e obrigatorio"})
		return
	}

	if err := c.authService.MFAVerifySetup(ctx.Request.Context(), userID, req.Code); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "mfa ativado com sucesso. login agora exigira codigo totp.",
	})
}

// MFAValidateLogin valida o codigo totp durante o fluxo de login.
// @Summary      validar mfa no login
// @Description  completa o login enviando o codigo totp + mfa_token recebido em /login.
// @Tags         mfa
// @Accept       json
// @Produce      json
// @Param        body  body      mfaLoginRequest  true  "token mfa + codigo totp"
// @Success      200   {object}  loginResponse
// @Failure      401   {object}  errorResponse
// @Router       /mfa/validate [post]
func (c *AuthController) MFAValidateLogin(ctx *gin.Context) {
	var req mfaLoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil || req.MFAToken == "" || req.Code == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "mfa_token e code sao obrigatorios"})
		return
	}

	access, refresh, err := c.authService.MFAValidateLogin(ctx.Request.Context(), req.MFAToken, req.Code)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// define cookies httponly apos validacao mfa
	c.setTokenCookies(ctx, access, refresh)

	ctx.JSON(http.StatusOK, gin.H{
		"message": "login com 2fa efetuado com sucesso",
	})
}

// MFADisable desativa o mfa do usuario autenticado.
// @Summary      desativar mfa
// @Description  desativa o mfa exigindo confirmacao com codigo totp atual.
// @Tags         mfa
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      mfaCodeRequest  true  "codigo totp"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  errorResponse
// @Failure      401   {object}  errorResponse
// @Router       /mfa/disable [post]
func (c *AuthController) MFADisable(ctx *gin.Context) {
	userID := ctx.GetString("user_id")
	if userID == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "token obrigatorio"})
		return
	}

	var req mfaCodeRequest
	if err := ctx.ShouldBindJSON(&req); err != nil || req.Code == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "codigo totp e obrigatorio"})
		return
	}

	if err := c.authService.MFADisable(ctx.Request.Context(), userID, req.Code); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "mfa desativado com sucesso.",
	})
}

// MFAStatus retorna se o mfa esta ativo para o usuario autenticado.
// @Summary      status do mfa
// @Description  retorna se o mfa esta ativo para o usuario.
// @Tags         mfa
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  mfaStatusResponse
// @Failure      401  {object}  errorResponse
// @Router       /mfa/status [get]
func (c *AuthController) MFAStatus(ctx *gin.Context) {
	userID := ctx.GetString("user_id")
	if userID == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "token obrigatorio"})
		return
	}

	enabled, err := c.authService.MFAStatus(ctx.Request.Context(), userID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"mfa_enabled": enabled,
	})
}

// --- tipos dto swagger (usados apenas para documentacao) ---

// loginRequest payload de login.
type loginRequest struct {
	Email    string `json:"email" example:"user@example.com"`
	Password string `json:"password" example:"strongpassword123"`
}

// loginResponse retornado apos login bem-sucedido.
type loginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// validateResponse retornado apos validacao bem-sucedida do token.
type validateResponse struct {
	Valid  bool   `json:"valid"`
	UserID string `json:"user_id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

// errorResponse resposta de erro generica.
type errorResponse struct {
	Error string `json:"error"`
}

// RegisterRequest dados esperados para criar uma nova conta.
type RegisterRequest struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

// MFA DTO types
type mfaSetupResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
	Message    string `json:"message"`
}

type mfaCodeRequest struct {
	Code string `json:"code" binding:"required" example:"123456"`
}

type mfaLoginRequest struct {
	MFAToken string `json:"mfa_token" binding:"required" example:"uuid-do-mfa-token"`
	Code     string `json:"code" binding:"required" example:"123456"`
}

type mfaStatusResponse struct {
	MFAEnabled bool `json:"mfa_enabled"`
}

// Register cria um novo usuario.
// @Summary      registro de nova conta
// @Description  cria um novo usuario e retorna os tokens de acesso imediatamente (auto-login).
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      RegisterRequest  true  "dados de registro"
// @Success      201   {object}  loginResponse
// @Failure      400   {object}  errorResponse
// @Router       /register [post]
func (c *AuthController) Register(ctx *gin.Context) {
	var req RegisterRequest

	// valida json
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "dados invalidos ou incompletos"})
		return
	}

	// chama servico
	access, refresh, err := c.authService.Register(
		ctx.Request.Context(),
		req.Name,
		req.Email,
		req.Password,
	)

	if err != nil {
		log.Printf("[register] falha: %v", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// define cookies httponly
	c.setTokenCookies(ctx, access, refresh)

	ctx.JSON(http.StatusCreated, gin.H{
		"message": "conta criada com sucesso",
	})
}
