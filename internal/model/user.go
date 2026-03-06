package model

import "github.com/google/uuid"

// User representa um usuario do sistema de autenticacao.
type User struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	Active       bool      `json:"active"`
}
