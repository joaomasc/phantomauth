package service

import (
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// hibpClient e um client http dedicado com timeout curto.
// se a api hibp estiver indisponivel, o registro prossegue (fail-open).
var hibpClient = &http.Client{Timeout: 3 * time.Second}

// checkPasswordPwned consulta a api haveibeenpwned (modelo k-anonymity)
// para verificar se a senha apareceu em vazamentos de dados conhecidos.
// apenas os primeiros 5 chars do hash sha-1 sao enviados.
// retorna count > 0 se comprometida, 0 se segura ou api indisponivel.
func checkPasswordPwned(password string) (int, error) {
	// sha-1 da senha
	h := sha1.New()
	h.Write([]byte(password))
	hash := fmt.Sprintf("%X", h.Sum(nil))

	prefix := hash[:5]
	suffix := hash[5:]

	// consulta range k-anonymity
	url := "https://api.pwnedpasswords.com/range/" + prefix
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "auth-service-security-check")
	req.Header.Set("Add-Padding", "true") // previne analise de timing

	resp, err := hibpClient.Do(req)
	if err != nil {
		// api indisponivel - fail-open
		return 0, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil
	}

	// busca o sufixo na lista retornada
	lines := strings.Split(string(body), "\r\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(parts[0], suffix) {
			var count int
			fmt.Sscanf(parts[1], "%d", &count)
			return count, nil
		}
	}

	return 0, nil
}
