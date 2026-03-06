package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joaomasc/auth-service/internal/model"
)

type RefreshTokenRepository interface {
	Save(ctx context.Context, token *model.RefreshToken) error
	FindByToken(ctx context.Context, token string) (*model.RefreshToken, error)
	Revoke(ctx context.Context, token string) error
	// RevokeAllForUser revoga todos os refresh tokens de um usuario.
	// usado quando reuso de token e detectado (possivel ataque).
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}

type refreshTokenRepository struct {
	db *pgxpool.Pool
}

func NewRefreshTokenRepository(db *pgxpool.Pool) RefreshTokenRepository {
	return &refreshTokenRepository{db: db}
}

func (r *refreshTokenRepository) Save(ctx context.Context, token *model.RefreshToken) error {
	query := `
		INSERT INTO auth_service.refresh_tokens (user_id, token, expires_at, revoked)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at;
	`
	return r.db.QueryRow(ctx, query,
		token.UserID,
		token.Token,
		token.ExpiresAt,
		token.Revoked,
	).Scan(&token.ID, &token.CreatedAt)
}

func (r *refreshTokenRepository) FindByToken(ctx context.Context, token string) (*model.RefreshToken, error) {
	query := `
		SELECT id, user_id, token, expires_at, revoked, created_at
		FROM auth_service.refresh_tokens
		WHERE token = $1;
	`
	rt := &model.RefreshToken{}
	err := r.db.QueryRow(ctx, query, token).
		Scan(&rt.ID, &rt.UserID, &rt.Token, &rt.ExpiresAt, &rt.Revoked, &rt.CreatedAt)
	if err != nil {
		return nil, err
	}
	return rt, nil
}

func (r *refreshTokenRepository) Revoke(ctx context.Context, token string) error {
	query := `
		UPDATE auth_service.refresh_tokens
		SET revoked = TRUE
		WHERE token = $1;
	`
	_, err := r.db.Exec(ctx, query, token)
	return err
}

func (r *refreshTokenRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE auth_service.refresh_tokens
		SET revoked = TRUE
		WHERE user_id = $1 AND revoked = FALSE;
	`
	_, err := r.db.Exec(ctx, query, userID)
	return err
}
