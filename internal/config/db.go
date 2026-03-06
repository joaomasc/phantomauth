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

	// ajuste do pool - valores razoaveis para um auth service
	config.MaxConns = 10
	config.MinConns = 2
	config.ConnConfig.ConnectTimeout = 10 * time.Second
	config.MaxConnIdleTime = 5 * time.Minute
	config.MaxConnLifetime = 1 * time.Hour
	config.HealthCheckPeriod = 30 * time.Second

	// timezone padrao do servidor
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET timezone = 'UTC'")
		return err
	}

	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		log.Fatalf("falha ao criar pool: %v", err)
	}

	// tenta conectar com retry - util para bancos serverless ou containers subindo
	var pingErr error
	for attempt := 1; attempt <= 5; attempt++ {
		pingCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		pingErr = db.Ping(pingCtx)
		cancel()

		if pingErr == nil {
			log.Println("conectado ao postgres com sucesso")
			return db
		}
		log.Printf("aguardando postgres (tentativa %d/5): %v", attempt, pingErr)
		time.Sleep(2 * time.Second)
	}

	log.Fatalf("postgres nao respondeu apos 5 tentativas: %v", pingErr)
	return nil
}
