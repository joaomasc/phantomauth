package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joaomasc/auth-service/internal/model"
)

// MFARepository gerencia dados mfa (totp) em auth_service.user_mfa.
type MFARepository interface {
	FindByUserID(ctx context.Context, userID uuid.UUID) (*model.UserMFA, error)
	Upsert(ctx context.Context, userID uuid.UUID, encryptedSecret string, enabled bool) error
	Enable(ctx context.Context, userID uuid.UUID) error
	Delete(ctx context.Context, userID uuid.UUID) error
}

type mfaRepository struct {
	db *pgxpool.Pool
}

func NewMFARepository(db *pgxpool.Pool) MFARepository {
	return &mfaRepository{db: db}
}

func (r *mfaRepository) FindByUserID(ctx context.Context, userID uuid.UUID) (*model.UserMFA, error) {
	mfa := &model.UserMFA{}
	err := r.db.QueryRow(ctx, `
		SELECT user_id, totp_secret, enabled, created_at, updated_at
		FROM auth_service.user_mfa
		WHERE user_id = $1
	`, userID).Scan(&mfa.UserID, &mfa.Secret, &mfa.Enabled, &mfa.CreatedAt, &mfa.UpdatedAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil // mfa nao configurado
		}
		return nil, err
	}
	return mfa, nil
}

func (r *mfaRepository) Upsert(ctx context.Context, userID uuid.UUID, encryptedSecret string, enabled bool) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO auth_service.user_mfa (user_id, totp_secret, enabled)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE
		SET totp_secret = $2, enabled = $3, updated_at = now()
	`, userID, encryptedSecret, enabled)
	return err
}

func (r *mfaRepository) Enable(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE auth_service.user_mfa SET enabled = TRUE, updated_at = now() WHERE user_id = $1
	`, userID)
	return err
}

func (r *mfaRepository) Delete(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		DELETE FROM auth_service.user_mfa WHERE user_id = $1
	`, userID)
	return err
}
