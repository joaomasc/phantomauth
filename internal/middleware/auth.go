package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/joaomasc/auth-service/internal/service"
)

// AuthRequired valida o phantom token e injeta as claims do usuario
// no contexto gin. le token do cookie httponly ou header authorization.
func AuthRequired(authService service.AuthServiceInterface, phantomCookieName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := ""

		// tenta cookie primeiro (browser com httponly)
		if tok, err := c.Cookie(phantomCookieName); err == nil && tok != "" {
			tokenStr = tok
		}

		// fallback: header authorization (api gateway / service-to-service)
		if tokenStr == "" {
			authHeader := c.GetHeader("Authorization")
			if authHeader == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token obrigatorio"})
				return
			}
			tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
			if tokenStr == authHeader {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "formato de token invalido"})
				return
			}
		}

		claims, err := authService.Introspect(c.Request.Context(), tokenStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token invalido ou expirado"})
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("email", claims.Email)
		c.Set("claims", claims)
		c.Next()
	}
}
