package config

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewDB(dsn string) *pgxpool.Pool {
	ctx := context.Background()

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		log.Fatalf("falha ao parsear config do db: %v", err)
	}

	// ajuste do pool - auth service faz poucas queries (login, validate, refresh)
	config.MaxConns = 10
	config.MinConns = 2                                 // manter 2 conexoes quentes para evitar cold start
	config.ConnConfig.ConnectTimeout = 10 * time.Second // 10s maximo para novas conexoes tcp
	config.MaxConnIdleTime = 4 * time.Minute            // < 5min timeout neon, evita conexoes mortas
	config.MaxConnLifetime = 1 * time.Hour
	config.HealthCheckPeriod = 30 * time.Second // detecta conexoes mortas rapido

	// timezone consistente
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET timezone = 'America/Sao_Paulo'")
		return err
	}

	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		log.Fatalf("falha ao criar pool: %v", err)
	}

	// neon e serverless - pode estar hibernando (cold start ate 60s).
	// tenta ate 10 vezes com timeout generoso.
	var pingErr error
	for attempt := 1; attempt <= 10; attempt++ {
		pingCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		pingErr = db.Ping(pingCtx)
		cancel()

		if pingErr == nil {
			log.Println("conectado ao postgres (neon) com sucesso")
			return db
		}
		log.Printf("neon db ainda acordando (tentativa %d/10): %v", attempt, pingErr)
		time.Sleep(3 * time.Second)
	}

	log.Fatalf("db nao respondeu apos 10 tentativas: %v", pingErr)
	return nil
}
