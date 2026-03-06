package model

import (
	"time"

	"github.com/google/uuid"
)

// UserMFA armazena dados mfa (totp) por usuario.
type UserMFA struct {
	UserID    uuid.UUID `json:"user_id"`
	Secret    string    `json:"-"` // segredo totp criptografado com aes-256-gcm, nunca exposto
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
