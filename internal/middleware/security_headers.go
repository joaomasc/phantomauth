package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders adiciona headers de seguranca em todas as respostas.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// previne browser de adivinhar tipo mime
		c.Header("X-Content-Type-Options", "nosniff")

		// impede pagina de ser embutida em iframe (clickjacking)
		c.Header("X-Frame-Options", "DENY")

		// forca https por 2 anos + preload list (hsts)
		c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

		// isola contexto do browser - previne acesso cross-origin a janelas/frames
		c.Header("Cross-Origin-Opener-Policy", "same-origin")

		// previne outros sites de ler respostas
		c.Header("Cross-Origin-Resource-Policy", "same-origin")

		// desabilita funcionalidades desnecessarias do browser
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")

		// nao vaza referer para outros dominios
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// csp: relaxado para swagger ui e frontend, estrito para o resto
		if strings.HasPrefix(c.Request.URL.Path, "/swagger/") || strings.HasPrefix(c.Request.URL.Path, "/app/") {
			c.Header("Content-Security-Policy",
				"default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		} else {
			c.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		}

		// desabilita cache em respostas de auth
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		c.Header("Pragma", "no-cache")

		c.Next()
	}
}
