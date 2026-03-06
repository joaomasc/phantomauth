package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// safeMethods sao metodos http que nao alteram estado - nao precisam de protecao csrf.
var safeMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
	http.MethodTrace:   true,
}

// CSRFProtection protege endpoints que alteram estado contra csrf via validacao do header origin.
//
// estrategia:
//   - metodos seguros (get, head, options, trace) sao sempre permitidos.
//   - requisicoes sem cookie de sessao sao chamadas machine-to-machine, permitidas.
//   - requisicoes com cookie (browser): header origin deve estar presente e na lista permitida.
func CSRFProtection(allowedOrigins []string, phantomCookieName string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = true
	}

	return func(c *gin.Context) {
		// metodos seguros - sem risco de csrf
		if safeMethods[c.Request.Method] {
			c.Next()
			return
		}

		// sem cookie de sessao = api gateway / servico interno, permitir
		if _, err := c.Cookie(phantomCookieName); err != nil {
			c.Next()
			return
		}

		// browser com cookie: validar origin
		origin := c.GetHeader("Origin")
		if origin == "" || !allowed[origin] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "origin nao permitida (csrf)",
			})
			return
		}

		c.Next()
	}
}
