-- Tabela para armazenar dados de MFA (TOTP) por utilizador.
-- O segredo TOTP é encriptado com AES-256-GCM antes de ser armazenado.

DROP TABLE IF EXISTS auth_service.user_mfa;
CREATE TABLE auth_service.user_mfa (
    user_id     UUID PRIMARY KEY REFERENCES auth_service.users(id),
    totp_secret TEXT NOT NULL,              -- Segredo TOTP encriptado (AES-256-GCM + base64)
    enabled     BOOLEAN DEFAULT FALSE,      -- MFA só fica ativo após verificação do primeiro código
    created_at  TIMESTAMP DEFAULT now(),
    updated_at  TIMESTAMP DEFAULT now()
);

COMMENT ON TABLE auth_service.user_mfa IS 'Armazena dados de MFA (TOTP/Google Authenticator) por utilizador. Segredo encriptado com AES-256-GCM.';
COMMENT ON COLUMN auth_service.user_mfa.totp_secret IS 'Segredo TOTP encriptado com AES-256-GCM. Nunca exposto em APIs.';
