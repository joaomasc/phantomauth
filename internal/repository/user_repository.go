package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joaomasc/auth-service/internal/model"
)

type UserRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{db: db}
}

// FindByEmail busca um usuario por email.
func (r *UserRepository) FindByEmail(email string) (model.User, error) {
	var u model.User

	query := `
		SELECT id, name, email, password_hash, role, active
		FROM auth_service.users
		WHERE email = $1 AND deleted_at IS NULL
	`

	err := r.db.QueryRow(context.Background(), query, email).Scan(
		&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.Role, &u.Active,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return u, errors.New("credenciais inválidas")
		}
		return u, err
	}

	return u, nil
}

// FindByID busca um usuario por uuid.
func (r *UserRepository) FindByID(id interface{ String() string }) (model.User, error) {
	var u model.User
	query := `
		SELECT id, name, email, password_hash, role, active
		FROM auth_service.users
		WHERE id = $1 AND deleted_at IS NULL
	`
	err := r.db.QueryRow(context.Background(), query, id).Scan(
		&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.Role, &u.Active,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return u, errors.New("utilizador não encontrado")
		}
		return u, err
	}
	return u, nil
}

// CreateUser insere um novo usuario.
func (r *UserRepository) CreateUser(ctx context.Context, name, email, passwordHash, role string) (model.User, error) {
	var user model.User

	query := `
		INSERT INTO auth_service.users (name, email, password_hash, role, active)
		VALUES ($1, $2, $3, $4, true)
		RETURNING id, name, email, role, active
	`

	err := r.db.QueryRow(ctx, query, name, email, passwordHash, role).Scan(
		&user.ID, &user.Name, &user.Email, &user.Role, &user.Active,
	)
	if err != nil {
		return model.User{}, err
	}

	return user, nil
}
