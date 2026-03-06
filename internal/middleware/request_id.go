package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequestID injeta um header x-request-id em cada requisicao.
// se o cliente ja envia (ex: api gateway), o valor e reaproveitado.
// caso contrario, um uuid v4 e gerado. util para correlacao de logs.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}

		c.Set("request_id", id)
		c.Header("X-Request-ID", id)

		c.Next()
	}
}
