package middleware

import (
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

// RequestTiming loga o tempo total de cada requisicao com nivel de severidade.
// util para identificar gargalos no neon (cold start), redis ou bcrypt.
func RequestTiming() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		duration := time.Since(start)
		status := c.Writer.Status()
		method := c.Request.Method
		path := c.Request.URL.Path

		level := "INFO "
		icon := "✅"
		switch {
		case duration > 30*time.Second:
			level = "SLOW "
			icon = "🐢🐢🐢"
		case duration > 5*time.Second:
			level = "SLOW "
			icon = "🐢🐢"
		case duration > 1*time.Second:
			level = "WARN "
			icon = "🐢"
		case status >= 500:
			level = "ERROR"
			icon = "❌"
		case status >= 400:
			level = "WARN "
			icon = "⚠️ "
		}

		log.Printf("[TIMING] %s %s | %d | %s | %s %s",
			icon, level, status, formatDuration(duration), method, path)
	}
}

// formatDuration formata uma duracao de forma legivel (ms ou s).
func formatDuration(d time.Duration) string {
	if d >= time.Second {
		return fmt.Sprintf("%.3fs", d.Seconds())
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}
