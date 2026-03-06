//go:build ignore

// Script utilitário para executar migrations no Neon/Postgres.
// Uso: go run scripts/migrate.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	dsn := os.Getenv("AUTH_DB_DSN")
	if dsn == "" {
		log.Fatal("AUTH_DB_DSN não configurado")
	}

	// Remover channel_binding que pode causar problema com pgx
	// e adicionar connect_timeout
	dsn = strings.Replace(dsn, "&channel_binding=require", "", 1)
	dsn = strings.Replace(dsn, "?channel_binding=require&", "?", 1)
	dsn = strings.Replace(dsn, "?channel_binding=require", "", 1)
	if strings.Contains(dsn, "?") {
		dsn += "&connect_timeout=30"
	} else {
		dsn += "?connect_timeout=30"
	}

	fmt.Println("Conectando ao Neon...")

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		log.Fatalf("Erro ao parsear DSN: %v", err)
	}
	cfg.MaxConns = 1

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		log.Fatalf("Erro ao conectar: %v", err)
	}
	defer db.Close()

	// Testar conexão
	fmt.Println("Fazendo ping...")
	if err := db.Ping(ctx); err != nil {
		log.Fatalf("Erro no ping: %v", err)
	}
	fmt.Println("✅ Conectado ao Postgres")

	// Migration 1: Schema + Users + Refresh Tokens
	// Executar statement por statement para evitar timeout em batch
	statements1 := []struct {
		label string
		sql   string
	}{
		{"schema auth_service", "CREATE SCHEMA IF NOT EXISTS auth_service"},
		{"auth_service.users", `CREATE TABLE IF NOT EXISTS auth_service.users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255) NOT NULL,
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role VARCHAR(50) NOT NULL DEFAULT 'admin',
			active BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT now(),
			updated_at TIMESTAMP DEFAULT now(),
			deleted_at TIMESTAMP
		)`},
		{"drop old refresh_tokens", "DROP TABLE IF EXISTS auth_service.refresh_tokens"},
		{"auth_service.refresh_tokens", `CREATE TABLE auth_service.refresh_tokens (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL REFERENCES auth_service.users(id),
			token VARCHAR(255) UNIQUE NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			revoked BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT now()
		)`},
		{"drop old user_mfa", "DROP TABLE IF EXISTS auth_service.user_mfa"},
		{"auth_service.user_mfa", `CREATE TABLE auth_service.user_mfa (
			user_id UUID PRIMARY KEY REFERENCES auth_service.users(id),
			totp_secret TEXT NOT NULL,
			enabled BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT now(),
			updated_at TIMESTAMP DEFAULT now()
		)`},
	}

	for _, s := range statements1 {
		stmtCtx, stmtCancel := context.WithTimeout(context.Background(), 15*time.Second)
		_, err := db.Exec(stmtCtx, s.sql)
		stmtCancel()
		if err != nil {
			log.Fatalf("❌ Erro em [%s]: %v", s.label, err)
		}
		fmt.Printf("  ✅ %s\n", s.label)
	}

	fmt.Println("\n🎉 Todas as migrations executadas com sucesso!")
}
