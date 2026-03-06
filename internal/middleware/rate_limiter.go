package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joaomasc/auth-service/internal/repository"
)

// RateLimiter cria um middleware gin que limita requisicoes por ip usando
// uma sliding window no redis (sorted set). protege contra brute force e credential stuffing.
func RateLimiter(tokenStore repository.TokenStore, limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		key := ip + ":" + c.FullPath()

		allowed, remaining, retryAfter, err := tokenStore.CheckRateLimit(
			c.Request.Context(), key, limit, window,
		)
		if err != nil {
			// fail-closed: se redis estiver fora, bloqueia a requisicao.
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error": "servico temporariamente indisponivel - tente novamente depois",
			})
			return
		}

		// rate limit headers (rfc 6585)
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

		if !allowed {
			retrySeconds := int(retryAfter.Seconds())
			if retrySeconds < 1 {
				retrySeconds = 1
			}
			c.Header("Retry-After", fmt.Sprintf("%d", retrySeconds))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":               "muitas tentativas - tente novamente depois",
				"retry_after_seconds": retrySeconds,
			})
			return
		}

		c.Next()
	}
}
