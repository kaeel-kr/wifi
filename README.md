# NumVirtual

Plataforma de números virtuais com recepção de códigos SMS em tempo real.
Não usa dependências externas: só precisa do Node.js 18 ou superior.

## Rodar

```bash
node server.js
```

Abra http://localhost:3000, crie uma conta e gere um número. Os créditos são ilimitados.

## Receber códigos reais

Por padrão o provedor é `simulated`: números e códigos são **fictícios** (demonstração).
Para receber SMS de verdade, copie `.env.example` para `.env` e preencha:

| Variável | Descrição |
|---|---|
| `PROVIDER` | `5sim` ou `smsactivate` |
| `PROVIDER_API_KEY` | Chave da API do provedor (a conta no provedor precisa ter saldo) |
| `JWT_SECRET` | Segredo com 32+ caracteres. **Defina em produção.** |
| `PORT` | Porta (padrão `3000`) |
| `TRUST_PROXY` | `1` se estiver atrás de proxy/HTTPS da hospedagem |

Reinicie com `node server.js`.
