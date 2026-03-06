#!/bin/bash
# ============================================================================
# Gerador de chaves RSA para JWT (RS256)
# ============================================================================
# Este script gera um par de chaves RSA (privada + pública) para assinar
# e validar tokens JWT com o algoritmo RS256 (assimétrico).
#
# - A chave PRIVADA é usada APENAS pelo Auth Service para ASSINAR tokens.
# - A chave PÚBLICA é usada pelos serviços consumidores para VALIDAR tokens,
#   sem capacidade de os falsificar.
#
# Uso:
#   chmod +x scripts/generate_keys.sh
#   ./scripts/generate_keys.sh
#
# As chaves serão geradas na pasta keys/
# ============================================================================

set -e

KEYS_DIR="keys"
PRIVATE_KEY="${KEYS_DIR}/private.pem"
PUBLIC_KEY="${KEYS_DIR}/public.pem"

echo "🔐 A gerar par de chaves RSA-2048 para JWT RS256..."
echo ""

# Criar diretória se não existir
mkdir -p "${KEYS_DIR}"

# Gerar chave privada RSA 2048-bit
openssl genrsa -out "${PRIVATE_KEY}" 2048 2>/dev/null

# Extrair chave pública
openssl rsa -in "${PRIVATE_KEY}" -pubout -out "${PUBLIC_KEY}" 2>/dev/null

# Proteger a chave privada (apenas o dono pode ler)
chmod 600 "${PRIVATE_KEY}"
chmod 644 "${PUBLIC_KEY}"

echo "✅ Chaves geradas com sucesso:"
echo "   🔑 Chave Privada: ${PRIVATE_KEY} (NUNCA partilhar!)"
echo "   🔓 Chave Pública: ${PUBLIC_KEY} (segura para distribuir)"
echo ""
echo "📋 Configuração no .env:"
echo "   JWT_PRIVATE_KEY_PATH=keys/private.pem"
echo "   JWT_PUBLIC_KEY_PATH=keys/public.pem"
echo ""
echo "⚠️  IMPORTANTE:"
echo "   - Adicione 'keys/private.pem' ao .gitignore"
echo "   - Em produção, use Docker Secrets ou Vault para a chave privada"
echo "   - NUNCA faça commit da chave privada no repositório"
