// logger estruturado de eventos de seguranca. saida json para stdout.
package audit

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

type EventType string

const (
	EventLoginSuccess      EventType = "LOGIN_SUCCESS"
	EventLoginFailure      EventType = "LOGIN_FAILURE"
	EventLoginMFARequired  EventType = "LOGIN_MFA_REQUIRED"
	EventMFASuccess        EventType = "MFA_SUCCESS"
	EventMFAFailure        EventType = "MFA_FAILURE"
	EventMFAEnabled        EventType = "MFA_ENABLED"
	EventMFADisabled       EventType = "MFA_DISABLED"
	EventLogout            EventType = "LOGOUT"
	EventTokenRefreshReuse EventType = "TOKEN_REFRESH_REUSE_DETECTED"
	EventRegister          EventType = "REGISTER"
	EventRegisterFailure   EventType = "REGISTER_FAILURE"
	EventAccountLocked     EventType = "ACCOUNT_LOCKED"
)

// Event representa uma entrada de auditoria.
type Event struct {
	Timestamp string    `json:"timestamp"`
	Event     EventType `json:"event"`
	RequestID string    `json:"request_id,omitempty"`
	UserID    string    `json:"user_id,omitempty"`
	Email     string    `json:"email,omitempty"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Success   bool      `json:"success"`
	Reason    string    `json:"reason,omitempty"`
	Extra     any       `json:"extra,omitempty"`
}

var logger = log.New(os.Stdout, "", 0)

// Log escreve o evento como json no stdout.
func Log(e Event) {
	e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(e)
	if err != nil {
		log.Printf("[AUDIT ERROR] falha ao serializar evento: %v", err)
		return
	}
	logger.Println(string(b))
}
