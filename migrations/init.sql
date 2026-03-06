-- Cria o schema auth se não existir
CREATE SCHEMA IF NOT EXISTS auth_service;

-- Tabela de utilizadores (auto-contida — não depende de schemas externos)
CREATE TABLE IF NOT EXISTS auth_service.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'admin',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now(),
    deleted_at TIMESTAMP
);

-- Recriar refresh_tokens com FK para auth_service.users (drop seguro da versão antiga)
DROP TABLE IF EXISTS auth_service.refresh_tokens;
CREATE TABLE auth_service.refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth_service.users(id),
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT now()
);