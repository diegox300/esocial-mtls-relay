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
// Por que extrair key/cert do PFX com node-forge em vez de entregar o PFX
// direto ao `https.request({ pfx, passphrase })`: o OpenSSL nativo que o Node
// usa para TLS recusa PKCS12 com criptografia legada (RC2-40/3DES, comum em
// certificados e-CNPJ A1 mais antigos) desde que o OpenSSL 3.x desativou esses
// algoritmos por padrão — falha com "Unsupported PKCS12 PFX data" mesmo com
// PFX e senha corretos (confirmado em produção). O node-forge é puro
// JavaScript e não tem essa restrição.
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
import forge from "node-forge";

export const config = {
  runtime: "nodejs",
};

const RELAY_SHARED_SECRET = process.env.RELAY_SHARED_SECRET || "";

// Hosts oficiais do webservice do eSocial. Confirmados contra
// base44/functions/esocialGovDireto/entry.ts (ENDPOINTS, linhas 30-39), que já
// usa esses mesmos hosts em produção — não são um palpite genérico.
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

/**
 * Extrai a chave privada e o certificado de um PFX/PKCS12, em PEM, usando o
 * node-forge (JavaScript puro).
 *
 * Por que não entregar o PFX direto ao `https.request({ pfx, passphrase })`:
 * o OpenSSL nativo que o Node usa para TLS (diferente do node-forge, que é
 * puramente JS) recusa PKCS12 com criptografia legada — RC2-40/3DES, comum
 * em certificados e-CNPJ A1 mais antigos — desde que o OpenSSL 3.x desativou
 * esses algoritmos por padrão. Isso falha com "Unsupported PKCS12 PFX data",
 * mesmo com o PFX e a senha corretos (confirmado em produção: o mesmo PFX
 * que o node-forge abre sem problema quebra o parser nativo do Node).
 * Extraindo key+cert em PEM aqui e usando `{ key, cert }` no lugar de
 * `{ pfx, passphrase }` evita depender do parser PKCS12 nativo do OpenSSL
 * por completo — só a etapa de TLS em si (apresentar o certificado já
 * decodificado) continua nativa.
 */
function extractKeyAndCertFromPfx(pfxBuffer: Buffer, password: string): { keyPem: string; certPem: string } {
  const p12Der = pfxBuffer.toString("binary");
  const p12Asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);

  let keyPem: string | null = null;
  let certPem: string | null = null;

  for (const safeContents of p12.safeContents) {
    for (const safeBag of safeContents.safeBags) {
      if (!keyPem && (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag || safeBag.type === forge.pki.oids.keyBag) && safeBag.key) {
        keyPem = forge.pki.privateKeyToPem(safeBag.key);
      }
      if (!certPem && safeBag.type === forge.pki.oids.certBag && safeBag.cert) {
        certPem = forge.pki.certificateToPem(safeBag.cert);
      }
    }
  }

  if (!keyPem || !certPem) {
    throw new Error("Não foi possível extrair chave privada e certificado do PFX (verifique a senha).");
  }

  return { keyPem, certPem };
}

function doMtlsRequest(params: {
  targetUrl: URL;
  method: string;
  headers: Record<string, string>;
  body: string;
  keyPem: string;
  certPem: string;
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
        key: params.keyPem,
        cert: params.certPem,
        // mTLS é bidirecional: exige certificado do cliente (key/cert acima) E
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

  let keyPem: string, certPem: string;
  try {
    const pfx = Buffer.from(cert_pfx_base64, "base64");
    ({ keyPem, certPem } = extractKeyAndCertFromPfx(pfx, cert_password));
  } catch (err) {
    res.status(400).json({
      error: `Falha ao processar cert_pfx_base64/cert_password: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }

  try {
    const result = await doMtlsRequest({
      targetUrl,
      method: method || "POST",
      headers: headers || {},
      body,
      keyPem,
      certPem,
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
