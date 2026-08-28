# Relay mTLS para o eSocial — Vercel

Peça de infraestrutura que falta para as funções `esocialGovDireto` e
`esocialGovTransmitir` (do projeto MeoSST, repositório
`meosstdrive-ui/meosst-tecnologia-ltda`, pasta `base44/functions/`)
conseguirem transmitir eventos ao eSocial de verdade. Ver a task `TASK-007`
e a decisão `ADR-002` naquele repositório para o contexto completo — este
repositório existe separado porque o deploy na Vercel precisa de conta
pessoal do GitHub, independente da organização dona do projeto principal.

## Por que isto existe

O eSocial exige mTLS (o servidor do governo pede um certificado do cliente no
handshake TLS, não só o contrário). O ambiente serverless do Base44 (Deno) não
consegue abrir esse tipo de conexão. Este projeto é um serviço HTTP pequeno,
hospedado separadamente na Vercel, que recebe a requisição do Base44 (com o
envelope SOAP + o certificado digital em PFX), faz a conexão mTLS real com o
governo, e devolve a resposta.

Node.js (não Edge) é obrigatório — só o runtime Node da Vercel dá acesso ao
módulo `https`/`tls` nativo necessário para apresentar um certificado cliente.
`vercel.json` e `api/relay.ts` já fixam `runtime: "nodejs"`.

## Contrato (já esperado pelo lado Base44)

O código em `base44/functions/esocialGovDireto/entry.ts` (`enviarViaMtlsRelay`)
já está pronto para chamar este relay assim:

**Requisição** — `POST <MTLS_RELAY_URL>`
```
Authorization: Bearer <MTLS_RELAY_SECRET>
Content-Type: application/json

{
  "target_url": "https://webservices.producaorestrita.esocial.gov.br/...",
  "method": "POST",
  "headers": { "Content-Type": "text/xml; charset=utf-8", "SOAPAction": "..." },
  "body": "<soap:Envelope>...</soap:Envelope>",
  "cert_pfx_base64": "<certificado .pfx em base64>",
  "cert_password": "<senha do certificado>"
}
```

**Resposta** — `200 OK`
```json
{ "status": 200, "body": "<soap:Envelope>...resposta do governo...</soap:Envelope>", "headers": {} }
```

Erro do relay (segredo errado, host não permitido, falha de conexão) devolve
`4xx`/`5xx` com `{ "error": "..." }` — a função Base44 já trata isso como
exceção, nunca finge sucesso.

## Trava de segurança adicionada (não estava no contrato original)

O contrato original deixaria este relay aceitar **qualquer** `target_url` —
ou seja, um proxy HTTPS aberto para quem tiver o segredo. `api/relay.ts`
adiciona uma **allowlist de host de destino** (`ESOCIAL_ALLOWED_HOSTS` ou o
padrão embutido no código): só hosts do webservice do eSocial passam. Confirme
a lista de hosts oficiais vigente na documentação técnica do eSocial antes de
ir para produção — os nomes usados aqui (`webservices.producaorestrita.esocial.gov.br`
para homologação/produção restrita, `webservices.esocial.gov.br` e
`webservices.consulta.esocial.gov.br` para produção) foram confirmados contra
`base44/functions/esocialGovDireto/entry.ts` (constante `ENDPOINTS`) no
repositório principal, que já usa esses mesmos hosts — não é um palpite.
Ainda assim, confirme contra a documentação oficial se o governo anunciar
mudança.

## Deploy na Vercel

1. **Crie um projeto novo na Vercel** apontando para este repositório — como
   ele é a raiz do próprio relay (não um subdiretório de um monorepo maior),
   não precisa configurar "Root Directory" na importação.
2. Configure as variáveis de ambiente do projeto na Vercel (Settings →
   Environment Variables):
   - `RELAY_SHARED_SECRET` — gere um valor aleatório forte, ex.:
     `openssl rand -hex 32`.
   - `ESOCIAL_ALLOWED_HOSTS` (opcional — só se precisar mudar a allowlist
     padrão).
3. Deploy. A Vercel vai expor uma URL do tipo
   `https://<seu-projeto>.vercel.app/api/relay`.
4. No painel do Base44, configure nas funções que usam o relay:
   - `MTLS_RELAY_URL` = `https://<seu-projeto>.vercel.app/api/relay`
   - `MTLS_RELAY_SECRET` = o MESMO valor de `RELAY_SHARED_SECRET` configurado
     na Vercel.

## Teste local

```bash
npm install
cp .env.example .env.local   # preencha RELAY_SHARED_SECRET
npm run dev
```

Depois, um `curl` de teste (sem certificado real, só para validar auth/allowlist):
```bash
curl -X POST http://localhost:3000/api/relay \
  -H "Authorization: Bearer <valor de RELAY_SHARED_SECRET>" \
  -H "Content-Type: application/json" \
  -d '{"target_url":"https://webservices.producaorestrita.esocial.gov.br/teste","body":"<xml/>","cert_pfx_base64":"","cert_password":""}'
```
(Vai falhar na etapa de conexão real sem um certificado válido — isso é
esperado; o teste local serve para validar autenticação e allowlist antes de
ter um certificado de homologação em mãos.)

## O que este relay NÃO faz

- Não guarda o certificado digital permanentemente — recebe o PFX a cada
  requisição e descarta depois de usar (não persiste em disco, não loga).
- Não decide política de negócio do eSocial — só transporta o envelope SOAP
  que o Base44 já montou e assinou.
- Não substitui a validação de schema/pré-transmissão que já existe em
  `esocialValidarPreTransmissao` no lado Base44.

## Limites da Vercel a observar

- `maxDuration` em `vercel.json` está em 30s — o plano Hobby da Vercel permite
  até 60s em funções Node; ajuste conforme necessário e conforme o plano
  contratado.
- Funções serverless da Vercel são stateless e podem ter cold start — para um
  fluxo de cadastro de funcionário/empresa (não é alto volume), isso não deve
  ser um problema, mas vale monitorar a latência em produção.

## Fonte

Cópia deployável de `infra/esocial-mtls-relay/` no repositório
`meosstdrive-ui/meosst-tecnologia-ltda`. Se aquele código mudar, repita a
cópia manualmente — não há sincronização automática entre os dois.
