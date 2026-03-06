package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config armazena todas as configuracoes do auth service.
// chaves rsa sao obrigatorias - use scripts/generate_keys.sh para gerar.
type Config struct {
	DBDsn     string
	RedisAddr string
	Port      string

	// "development" ou "production"
	Environment string

	// jwt rs256 (assimetrico)
	JWTPrivateKey *rsa.PrivateKey // assina tokens - nunca exponha
	JWTPublicKey  *rsa.PublicKey  // valida tokens - seguro para distribuir

	// mfa (totp)
	MFAEncryptionKey []byte // chave aes-256-gcm para segredos totp no db

	// issuer para claims jwt e totp
	Issuer string

	// cookies
	CookieSecure bool // true em producao (https), false em dev (http)

	// rate limiting
	RateLimitLogin    int           // max tentativas de login por ip/janela (padrao: 5)
	RateLimitRegister int           // max registros por ip/janela (padrao: 3)
	RateLimitWindow   time.Duration // janela de rate limit (padrao: 1min)

	// ttls dos tokens
	PhantomTokenTTL time.Duration // ttl do phantom token no redis (padrao: 5min)
	RefreshTokenTTL time.Duration // validade do refresh token (padrao: 7 dias)
}

func LoadConfig() *Config {
	_ = godotenv.Load()

	privateKey := loadRSAPrivateKey()

	cfg := &Config{
		DBDsn:     getEnvStrict("AUTH_DB_DSN"),
		RedisAddr: getEnvStrict("AUTH_REDIS_ADDR"),
		Port:      getEnv("AUTH_PORT", "8081"),

		Environment: getEnv("AUTH_ENV", "development"),

		JWTPrivateKey: privateKey,
		JWTPublicKey:  &privateKey.PublicKey,

		MFAEncryptionKey: loadMFAEncryptionKey(),

		Issuer: getEnv("AUTH_ISSUER", "auth-service"),

		CookieSecure: getEnv("COOKIE_SECURE", "false") == "true",

		RateLimitLogin:    getEnvInt("RATE_LIMIT_LOGIN", 5),
		RateLimitRegister: getEnvInt("RATE_LIMIT_REGISTER", 3),
		RateLimitWindow:   getEnvDuration("RATE_LIMIT_WINDOW", 1*time.Minute),

		PhantomTokenTTL: getEnvDuration("PHANTOM_TOKEN_TTL", 5*time.Minute),
		RefreshTokenTTL: getEnvDuration("REFRESH_TOKEN_TTL", 7*24*time.Hour),
	}

	// forca cookies seguros em producao como failsafe
	if cfg.Environment == "production" {
		cfg.CookieSecure = true
	}

	return cfg
}

// loadRSAPrivateKey carrega a chave privada rsa de um arquivo pem ou variavel de ambiente.
// suporta pkcs#1 e pkcs#8.
func loadRSAPrivateKey() *rsa.PrivateKey {
	var pemData []byte
	var err error

	// tenta arquivo primeiro
	if keyPath := os.Getenv("JWT_PRIVATE_KEY_PATH"); keyPath != "" {
		pemData, err = os.ReadFile(keyPath)
		if err != nil {
			log.Fatalf("\u274c failed to read private key from %s: %v", keyPath, err)
		}
	} else if keyPEM := os.Getenv("JWT_PRIVATE_KEY"); keyPEM != "" {
		// conteudo pem raw (docker secrets / ci)
		pemData = []byte(keyPEM)
	} else {
		log.Fatal("\u274c CRITICO: defina JWT_PRIVATE_KEY_PATH ou JWT_PRIVATE_KEY.\n" +
			"   Use 'scripts/generate_keys.sh' para gerar as chaves rsa.")
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		log.Fatal("\u274c chave privada rsa invalida (pem decode falhou)")
	}

	// tenta pkcs#8 primeiro (formato moderno), depois pkcs#1
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		pkcs1Key, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err2 != nil {
			log.Fatalf("\u274c falha ao parsear chave privada rsa: PKCS8=%v PKCS1=%v", err, err2)
		}
		return pkcs1Key
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("\u274c chave privada nao e rsa")
	}
	return rsaKey
}

// loadMFAEncryptionKey carrega a chave aes-256 para criptografia do segredo totp.
func loadMFAEncryptionKey() []byte {
	key := os.Getenv("MFA_ENCRYPTION_KEY")
	if key == "" {
		log.Fatal("\u274c CRITICO: defina MFA_ENCRYPTION_KEY (min 32 chars para aes-256).")
	}
	keyBytes := []byte(key)
	if len(keyBytes) < 32 {
		log.Fatal("\u274c MFA_ENCRYPTION_KEY deve ter pelo menos 32 caracteres")
	}
	return keyBytes[:32] // aes-256 requer exatamente 32 bytes
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// getEnvStrict encerra o processo se a variavel estiver ausente. seguranca primeiro.
func getEnvStrict(key string) string {
	value, exists := os.LookupEnv(key)
	if !exists || value == "" {
		log.Fatalf("\u274c CRITICAL: env var %s is not set.", key)
	}
	return value
}

func getEnvInt(key string, fallback int) int {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return n
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return fallback
	}
	return d
}
