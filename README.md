# Auth Service 🔐

Serviço de autenticação Phantom Token, construído em **Go**. Implementa as melhores práticas de segurança e pode ser clonado e adaptado a qualquer projeto.

---

## 🚀 Arquitetura: Phantom Token Pattern

Para garantir a máxima segurança e performance, este serviço implementa o **Phantom Token Pattern**:

1. **Token Opaco (Externo):** O frontend recebe um UUID opaco gerado pelo serviço. Se interceptado, este token não contém dados sensíveis do utilizador.
2. **JWT Real (Interno):** No Redis, este UUID está vinculado a um JWT assinado com **RS256** (chave assimétrica RSA) que contém as `claims` do utilizador, como `user_id`, `email`, `role`.
3. **Introspecção:** O seu backend consome a rota `/validate` para trocar o token opaco pelos dados reais do utilizador, validados com a chave pública RSA.

---

## 🛡 Funcionalidades de Segurança

| Funcionalidade | Descrição |
|---|---|
| **JWT RS256 (Assimétrico)** | Tokens assinados com chave privada RSA. Serviços consumidores validam com a chave pública — nunca podem falsificar tokens. |
| **MFA / TOTP** | Autenticação multifator via qualquer aplicação TOTP (RFC 6238). Segredos TOTP encriptados com AES-256-GCM na base de dados. |
| **Rate Limiting** | Sliding window no Redis protege `/login` (5/min), `/register` (3/min), `/mfa/validate` (5/min) por IP. |
| **Phantom Token TTL Reduzido** | TTL de 5 minutos (configurável). Se um utilizador for desativado, o token é rejeitado imediatamente via verificação de revogação no Redis. |
| **Refresh Token Rotation** | Rotação automática com deteção de reuso — se um refresh token revogado for reutilizado, toda a sessão é eliminada. |
| **Security Headers** | HSTS, X-Frame-Options DENY, CSP, X-Content-Type-Options, no-cache. |
| **bcrypt cost=12** | Passwords criptografadas com custo elevado. |

---

## 🛠 Tecnologias

- **Linguagem:** Go 1.25.1  
- **Framework Web:** Gin Gonic  
- **Banco de Dados:** PostgreSQL (schema `auth_service` auto-contido com tabelas `users`, `refresh_tokens` e `user_mfa`)  
- **Cache/Store:** Redis para Phantom Tokens, Rate Limiting, MFA sessions e User Revocation  
- **Documentação:** Swagger / OpenAPI 2.0  
- **Containerização:** Docker & Docker Compose  
- **MFA:** TOTP (RFC 6238) via `pquerna/otp`  

---

## 📂 Estrutura do Projeto

```text
/auth-service
├── cmd/server/main.go          # Ponto de entrada e configuração de rotas
├── internal/
│   ├── controller/             # Handlers HTTP (Login, Register, Validate, MFA)
│   ├── service/                # Lógica de negócio (Auth + MFA + Crypto)
│   ├── repository/             # Acesso a dados (Postgres e Redis)
│   ├── model/                  # Definição de estruturas (User, RefreshToken, UserMFA)
│   ├── token/                  # Geração de JWT RS256 e tokens opacos
│   ├── middleware/             # Rate Limiter, Security Headers, Auth, Timing
│   └── config/                 # Gestão de variáveis de ambiente, RSA keys e conexões
├── keys/                       # Par de chaves RSA (⚠️ DEMO — ver aviso abaixo)
├── migrations/                 # Scripts SQL (users, refresh_tokens, user_mfa)
├── scripts/                    # Script para gerar chaves RSA
└── docs/                       # Documentação Swagger auto-gerada
```

---

## ⚠️ Aviso sobre as Chaves RSA (`keys/`)

As chaves RSA incluídas neste repositório são **exclusivamente para demonstração e desenvolvimento**.

> **🚨 Em produção, TROQUE OBRIGATORIAMENTE as chaves RSA!**  
> Qualquer pessoa com acesso a este repositório pode assinar tokens válidos com a chave privada aqui publicada.

**Para gerar novas chaves:**
```bash
# Linux/Mac
./scripts/generate_keys.sh

# Windows (PowerShell com Git)
$ssl = (Split-Path (Get-Command git).Source -Parent) + "\..\usr\bin\openssl.exe"
& $ssl genrsa -out keys/private.pem 2048
& $ssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

Em produção, as chaves devem ser injetadas via:
- **Docker Secrets**
- **HashiCorp Vault**
- **Variáveis de ambiente** (`JWT_PRIVATE_KEY` com o PEM inline)

---

## 🔑 Configuração (Variáveis de Ambiente)

| Variável | Obrigatória | Descrição |
|---|---|---|
| `AUTH_DB_DSN` | ✅ | String de conexão ao Postgres |
| `AUTH_REDIS_ADDR` | ✅ | Endereço de conexão ao Redis |
| `JWT_PRIVATE_KEY_PATH` | ✅* | Caminho para a chave privada RSA (ex: `keys/private.pem`) |
| `JWT_PRIVATE_KEY` | ✅* | Alternativa: conteúdo PEM inline (para Docker/CI) |
| `MFA_ENCRYPTION_KEY` | ✅ | Chave AES-256 (mínimo 32 caracteres) para encriptar segredos TOTP |
| `AUTH_PORT` | ❌ | Porta de execução (padrão: `8081`) |
| `PHANTOM_TOKEN_TTL` | ❌ | TTL do phantom token (padrão: `5m`) |
| `REFRESH_TOKEN_TTL` | ❌ | Validade do refresh token (padrão: `168h` / 7 dias) |
| `RATE_LIMIT_LOGIN` | ❌ | Tentativas de login por IP/min (padrão: `5`) |
| `RATE_LIMIT_REGISTER` | ❌ | Registos por IP/min (padrão: `3`) |
| `RATE_LIMIT_WINDOW` | ❌ | Janela do rate limit (padrão: `1m`) |

*\* Uma das duas é obrigatória: `JWT_PRIVATE_KEY_PATH` ou `JWT_PRIVATE_KEY`*

---

## 🛣 Endpoints (API v1)

### Auth

| Método | Rota | Proteção | Descrição |
|---|---|---|---|
| POST | `/api/v1/auth/login` | Rate Limit | Autenticação. Se MFA ativo, retorna `mfa_token`. |
| POST | `/api/v1/auth/register` | Rate Limit | Registo de utilizador com auto-login. |
| POST | `/api/v1/auth/refresh` | Rate Limit | Rotação de refresh token. |
| POST | `/api/v1/auth/validate` | — | Introspecção do Phantom Token (uso interno). |
| POST | `/api/v1/auth/logout` | — | Destrói sessão (phantom token + refresh token). |

### MFA (TOTP)

| Método | Rota | Proteção | Descrição |
|---|---|---|---|
| POST | `/api/v1/auth/mfa/setup` |  Token | Gera segredo TOTP (QR code). |
| POST | `/api/v1/auth/mfa/verify-setup` |  Token | Valida 1º código e ativa MFA. |
| POST | `/api/v1/auth/mfa/validate` | Rate Limit | Completa login com código TOTP. |
| POST | `/api/v1/auth/mfa/disable` |  Token | Desativa MFA (exige código). |
| GET | `/api/v1/auth/mfa/status` |  Token | Retorna se MFA está ativo. |

---

## 🔄 Fluxo de Login com MFA

```
Frontend                    Auth Service                  Redis / DB
   │                             │                            │
   │─── POST /login ────────────►│                            │
   │    {email, password}        │── FindByEmail ────────────►│
   │                             │◄── user data ──────────────│
   │                             │── bcrypt verify            │
   │                             │── Check MFA enabled ──────►│
   │                             │◄── MFA enabled ────────────│
   │◄── {mfa_required, token} ──│── Save MFA token ───────-──►│
   │                             │                            │
   │─── POST /mfa/validate ────►│                             │
   │    {mfa_token, code}        │── Get MFA token ──────────►│
   │                             │── Validate TOTP            │
   │                             │── Generate JWT RS256       │
   │                             │── Save phantom ───────────►│
   │◄── {access, refresh} ──────│                             │
```

---

## 🛠 Como Executar

### Gerar Chaves RSA (apenas 1ª vez)

```bash
# Linux/Mac
chmod +x scripts/generate_keys.sh
./scripts/generate_keys.sh

# Windows (PowerShell com Git instalado)
$ssl = (Split-Path (Get-Command git).Source -Parent) + "\..\usr\bin\openssl.exe"
& $ssl genrsa -out keys/private.pem 2048
& $ssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

### Ambiente Local com Docker

```bash
docker-compose up -d
```

### Execução Manual (Go)

```bash
go mod download
# Configurar .env (ver tabela acima)
go run cmd/server/main.go
```

Servidor disponível em `http://localhost:8081` | Swagger em `http://localhost:8081/swagger/index.html`

---

## 📌 Observações

Este é um repositório **público e educacional**.  
As chaves RSA incluídas são para demonstração — **nunca devem ser usadas em produção**.

---

## 🌐 Frontend de Demonstração

O projecto inclui um frontend funcional em `frontend/` (HTML/CSS/JS puro) que demonstra todo o fluxo:

- Login / Registo com validação de password em tempo real (OWASP)
- Dashboard com informações do token e sessão
- Ativação/desativação de 2FA com QR code (qualquer aplicação TOTP)
- Refresh automático de token
- Logout real

Acesse em `http://localhost:8081/app/` após iniciar o servidor.

---

## 🔀 Integração com API Gateway (Produção)

Num cenário real com múltiplos microserviços, um **API Gateway** (Traefik, Nginx, Caddy, Kong) chamaria `POST /api/v1/auth/validate` antes de repassar requests aos serviços internos:

```
Frontend ──▶ API Gateway ──┬──▶ POST /validate (Auth Service) ──▶ 200 OK
                           │
                           └──▶ Repassa request com X-User-ID ao microserviço
```

O Auth Service já está **pronto para esse cenário** — o `/validate` foi desenhado exactamente para consumo por gateways via `forward_auth`.