// Relay mTLS para o eSocial — hospedado na Vercel (Node.js runtime).
//
// Implementa exatamente o contrato que base44/functions/esocialGovDireto/entry.ts
// já espera (função enviarViaMtlsRelay): recebe o envelope SOAP + o certificado
// digital (PFX em base64 + senha) do backend Base44, abre a conexão HTTPS com
// mTLS de verdade contra o webservice do eSocial (algo que o ambiente serverless
// do Base44 não consegue fazer sozinho), e devolve a resposta.
//
// Por que Node.js e não Edge: mTLS exige apresentar um certificado cliente no
// handshake TLS — isso usa o módulo `https`/`tls` nativo do Node, que só roda
// no runtime Node.js da Vercel, não no Edge Runtime (sem acesso a socket TLS
// bruto). `export const config` abaixo fixa isso.
//
// Segurança:
// - Autenticação por segredo compartilhado (Authorization: Bearer <RELAY_SHARED_SECRET>),
//   comparado em tempo constante.
// - Allowlist de host de destino (ESOCIAL_ALLOWED_HOSTS) — o contrato original
//   deixaria este relay aceitar qualquer target_url; sem essa trava, o relay
//   viraria um proxy HTTP aberto para quem tiver o segredo. Só hosts do eSocial
//   (ou os que você adicionar explicitamente) passam.
// - Nunca loga corpo de requisição, certificado, senha ou segredo — só metadados
//   (host de destino, status HTTP, duração).
// - `rejectUnauthorized: true` sempre — valida o certificado do SERVIDOR do
//   governo também (mTLS é bidirecional: cliente prova quem é, servidor também).

import type { VercelRequest, VercelResponse } from "@vercel/node";
import https from "node:https";
import { URL } from "node:url";
import crypto from "node:crypto";

export const config = {
  runtime: "nodejs",
};

const RELAY_SHARED_SECRET = process.env.RELAY_SHARED_SECRET || "";

// Hosts oficiais do webservice do eSocial. Confirme a lista vigente na
// documentação técnica oficial do eSocial antes de usar em produção — nomes de
// host de ambiente de produção restrita (homologação) e produção mudam raramente,
// mas mudam. Adicione aqui, nunca aceite host fora desta lista.
const DEFAULT_ALLOWED_HOSTS = [
  "webservices.producaorestrita.esocial.gov.br", // homologação / produção restrita (envio + consulta)
  "webservices.esocial.gov.br", // produção — envio de lotes
  "webservices.consulta.esocial.gov.br", // produção — consulta de lotes
];

function getAllowedHosts(): string[] {
  const fromEnv = (process.env.ESOCIAL_ALLOWED_HOSTS || "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  return fromEnv.length > 0 ? fromEnv : DEFAULT_ALLOWED_HOSTS;
}

function timingSafeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Ainda assim compara contra si mesmo para não vazar timing pelo tamanho.
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

interface RelayRequestBody {
  target_url: string;
  method?: string;
  headers?: Record<string, string>;
  body: string;
  cert_pfx_base64: string;
  cert_password: string;
}

interface RelayResponseBody {
  status: number;
  body: string;
  headers: Record<string, string>;
}

function doMtlsRequest(params: {
  targetUrl: URL;
  method: string;
  headers: Record<string, string>;
  body: string;
  pfx: Buffer;
  passphrase: string;
  timeoutMs: number;
}): Promise<RelayResponseBody> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: params.targetUrl.hostname,
        port: params.targetUrl.port || 443,
        path: `${params.targetUrl.pathname}${params.targetUrl.search}`,
        method: params.method,
        headers: {
          ...params.headers,
          "Content-Length": Buffer.byteLength(params.body),
        },
        pfx: params.pfx,
        passphrase: params.passphrase,
        // mTLS é bidirecional: exige certificado do cliente (pfx acima) E
        // valida o certificado do servidor do governo. Nunca desative isto.
        rejectUnauthorized: true,
        timeout: params.timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const responseHeaders: Record<string, string> = {};
          for (const [key, value] of Object.entries(res.headers)) {
            if (typeof value === "string") responseHeaders[key] = value;
            else if (Array.isArray(value)) responseHeaders[key] = value.join(", ");
          }
          resolve({
            status: res.statusCode || 0,
            body: Buffer.concat(chunks).toString("utf-8"),
            headers: responseHeaders,
          });
        });
      }
    );

    req.on("timeout", () => {
      req.destroy(new Error(`Timeout de ${params.timeoutMs}ms ao conectar em ${params.targetUrl.hostname}`));
    });

    req.on("error", (err) => {
      // Nunca incluir params.body/pfx/passphrase na mensagem de erro.
      reject(new Error(`Erro de conexão mTLS com ${params.targetUrl.hostname}: ${err.message}`));
    });

    req.write(params.body);
    req.end();
  });
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const startedAt = Date.now();

  if (req.method !== "POST") {
    res.status(405).json({ error: "Método não permitido. Use POST." });
    return;
  }

  if (!RELAY_SHARED_SECRET) {
    // Falha aberta seria pior que recusar: sem segredo configurado, o relay
    // recusa TUDO, nunca aceita sem autenticação.
    res.status(500).json({ error: "RELAY_SHARED_SECRET não configurado no relay." });
    return;
  }

  const authHeader = req.headers["authorization"] || "";
  const expected = `Bearer ${RELAY_SHARED_SECRET}`;
  if (!timingSafeEqual(String(authHeader), expected)) {
    res.status(401).json({ error: "Não autorizado." });
    return;
  }

  let payload: RelayRequestBody;
  try {
    payload = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    res.status(400).json({ error: "Corpo da requisição não é JSON válido." });
    return;
  }

  const { target_url, method, headers, body, cert_pfx_base64, cert_password } = payload || {};

  if (!target_url || !body || !cert_pfx_base64 || cert_password === undefined) {
    res.status(400).json({
      error: "Campos obrigatórios ausentes: target_url, body, cert_pfx_base64, cert_password.",
    });
    return;
  }

  let targetUrl: URL;
  try {
    targetUrl = new URL(target_url);
  } catch {
    res.status(400).json({ error: "target_url inválida." });
    return;
  }

  if (targetUrl.protocol !== "https:") {
    res.status(400).json({ error: "target_url precisa ser https." });
    return;
  }

  const allowedHosts = getAllowedHosts();
  if (!allowedHosts.includes(targetUrl.hostname.toLowerCase())) {
    // Sem isto, este relay seria um proxy HTTPS aberto para qualquer host,
    // para quem tiver o segredo — mesmo sendo um segredo forte, é uma
    // superfície de ataque desnecessária (SSRF). Recusa explícita, não silenciosa.
    res.status(403).json({
      error: `Host de destino não permitido: ${targetUrl.hostname}. Hosts permitidos: ${allowedHosts.join(", ")}.`,
    });
    return;
  }

  let pfx: Buffer;
  try {
    pfx = Buffer.from(cert_pfx_base64, "base64");
  } catch {
    res.status(400).json({ error: "cert_pfx_base64 inválido." });
    return;
  }

  try {
    const result = await doMtlsRequest({
      targetUrl,
      method: method || "POST",
      headers: headers || {},
      body,
      pfx,
      passphrase: cert_password,
      timeoutMs: Number(process.env.RELAY_TIMEOUT_MS || 30000),
    });

    // Log só de metadados — nunca corpo, certificado, senha ou segredo.
    console.log(
      JSON.stringify({
        event: "esocial_mtls_relay_request",
        host: targetUrl.hostname,
        status: result.status,
        duration_ms: Date.now() - startedAt,
      })
    );

    res.status(200).json(result satisfies RelayResponseBody);
  } catch (err) {
    console.log(
      JSON.stringify({
        event: "esocial_mtls_relay_error",
        host: targetUrl.hostname,
        error: err instanceof Error ? err.message : String(err),
        duration_ms: Date.now() - startedAt,
      })
    );
    res.status(502).json({
      error: err instanceof Error ? err.message : "Erro desconhecido no relay.",
    });
  }
}
