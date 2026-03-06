# ⚠️ CHAVES DE DEMONSTRAÇÃO — NÃO USAR EM PRODUÇÃO

As chaves RSA nesta pasta são **exclusivamente para demonstração e desenvolvimento**.

Qualquer pessoa com acesso a este repositório pode:
- Assinar tokens JWT válidos com `private.pem`
- Validar tokens com `public.pem`

## Em Produção

Substitua estas chaves por chaves geradas localmente e NUNCA as commite no repositório:

```bash
# Gerar novas chaves
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

Injete via **Docker Secrets**, **HashiCorp Vault** ou **variável de ambiente** (`JWT_PRIVATE_KEY`).
