# Etapa 1: Builder (Compila o código)
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Instalar dependências básicas para compilação (se necessário)
RUN apk add --no-cache git

# Baixar módulos (Cache Layer)
COPY go.mod go.sum ./
RUN go mod download

# Copiar código fonte
COPY . .

# Compilar binário estático
RUN CGO_ENABLED=0 GOOS=linux go build -o auth-server ./cmd/server/main.go

# Etapa 2: Runner (Imagem leve para produção)
FROM alpine:latest

WORKDIR /app

# Copiar binário da etapa anterior
COPY --from=builder /app/auth-server .

# Copiar chaves RSA (em produção, usar Docker Secrets ou montar via volume)
# COPY --from=builder /app/keys ./keys

# Expor porta
EXPOSE 8081

# Comando de execução
CMD ["./auth-server"]