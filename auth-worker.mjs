/**
 * EVN CSKH Web - Cloudflare Workers Authentication & Security Worker
 *
 * Architecture & Security Model:
 * 1. WebCrypto PBKDF2-SHA256: 600,000 iterations, 16-byte salt (32 hex chars), 32-byte hash (64 hex chars).
 *    Note on Free Plan CPU Limit: WebCrypto PBKDF2 with 600,000 iterations is computationally intensive.
 *    Proof of execution on Cloudflare Workers free CPU limit is pending; per specification,
 *    no weakening of iterations (600,000) or salt/hash lengths is permitted.
 * 2. Credential Registry: Read-only fine-grained access to GitHub PRIVATE repository accounts.json.
 *    Repository privacy is verified via GitHub API (api.github.com/repos/{owner}/{repo}).
 *    Public repos, redirects, non-GitHub hosts, bodies > 1MiB, or schema violations are strictly rejected.
 * 3. Cache & Stale Policy: Successful registry cached in-memory for max 60 seconds (env-keyed).
 *    Cache key includes GITHUB_TOKEN and SESSION_SECRET credentials (never logged).
 *    No stale data on failure: If GitHub fetch fails, operation fails immediately with 503.
 * 4. Token & Session: Cookie __Host-cskh_session (HttpOnly, Secure, SameSite=Strict, Path=/, TTL 8h).
 *    Signed HMAC-SHA256 token containing subject (username), expiration, and cryptographic fingerprint
 *    of (password_hash + salt). Any password rotation, account deactivation, or deletion invalidates
 *    existing sessions within the 60s cache window.
 * 5. Rate Limiting: Cloudflare native rate limits binding AUTH_RATE_LIMIT mandatory on login.
 *    Dual-key check: ip+username and ip aggregate.
 *    Client IP strictly trusts cf-connecting-ip; never trusts attacker-supplied x-forwarded-for.
 *    Any rate limit exception, undefined, or malformed result fails with 503 (fail closed).
 *    Note on Cloudflare Workers Rate Limiting: Counters are edge-approximate and asynchronously synchronized
 *    across distributed global data centers.
 * 6. Asset Routing & Protection:
 *    - Public Static: / , /index.html , /manifest.json , /sw.js , /data/overview.json , /data/stations.json.
 *    - Data stations.json & overview.json: Whitelists summary fields only with scalar-only values;
 *      strips arbitrary or sensitive fields; parse failures return 503 with no raw fallback.
 *    - Protected Station Partitions: /data/stations/[A-Za-z0-9_-]+.json and /static/data/stations alias.
 *      Unauthenticated requests receive 401 (never real customer JSON).
 *      Authenticated responses set Cache-Control: no-store, no-cache, must-revalidate, private.
 *    - Denied Paths: auth-worker.mjs, wrangler.json, accounts*.json, .git, node_modules, unknown -> 404.
 * 7. Outer Error Wrapper:
 *    - Catches any unhandled exceptions, returns generic 503 with no raw secrets or stack traces.
 *    - Enforces no-store on all responses.
 */

export const PBKDF2_ITERATIONS = 600000;
export const PBKDF2_SALT_BYTES = 16; // 32 hex chars
export const PBKDF2_HASH_BYTES = 32; // 64 hex chars
export const SESSION_COOKIE_NAME = "__Host-cskh_session";
export const SESSION_TTL_SECONDS = 8 * 60 * 60; // 8 hours = 28,800s
export const REGISTRY_CACHE_TTL_MS = 60 * 1000; // 60 seconds
export const MAX_REGISTRY_BYTES = 1024 * 1024; // 1 MiB
export const MAX_LOGIN_BODY_BYTES = 4096;
export const MAX_USERS_COUNT = 1000;
export const USERNAME_REGEX = /^[a-z0-9][a-z0-9_.-]{2,63}$/;
export const HEX_32_REGEX = /^[0-9a-fA-F]{32}$/;
export const HEX_64_REGEX = /^[0-9a-fA-F]{64}$/;
export const REPO_FORMAT_REGEX = /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/;
export const GITHUB_HOST = "api.github.com";
export const DEFAULT_AUTH_BRANCH = "main";

export const OVERVIEW_WHITELIST = new Set([
  "total_points",
  "total_stations",
  "installed_count",
  "uninstalled_count",
  "installed_rate",
  "target_rate",
  "target_achieved",
  "org_name",
  "cms_sync_time",
  "cmis_sync_time",
  "exported_at"
]);

export const STATION_ROOT_WHITELIST = new Set([
  "total_stations",
  "exported_at",
  "cms_sync_time",
  "cmis_sync_time"
]);

export const STATION_SUMMARY_WHITELIST = new Set([
  "station_id",
  "station_name",
  "total_customers",
  "installed_count",
  "uninstalled_count",
  "installed_rate",
  "unique_uninst_phones",
  "saved_calls",
  "status_badge"
]);

const PUBLIC_STATIC_PATHS = new Set([
  "/",
  "/index.html",
  "/manifest.json",
  "/sw.js",
  "/data/overview.json",
  "/data/stations.json"
]);

const PROTECTED_STATION_REGEX = /^\/data\/stations\/([A-Za-z0-9_-]+)\.json$/;
const PROTECTED_STATION_ALIAS_REGEX = /^\/static\/data\/stations\/([A-Za-z0-9_-]+)\.json$/;

// ============================================================================
// Cryptographic & Encoding Utilities (WebCrypto)
// ============================================================================

export function hexToUint8Array(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const byte = parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) throw new Error("Invalid hex byte");
    array[i] = byte;
  }
  return array;
}

export function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

export function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export function base64UrlEncode(uint8Array) {
  let binary = "";
  for (let i = 0; i < uint8Array.length; i++) {
    binary += String.fromCharCode(uint8Array[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function base64UrlDecode(str) {
  let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) {
    b64 += "=";
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function computePbkdf2Hash(password, saltHex, iterations = PBKDF2_ITERATIONS) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const saltBytes = hexToUint8Array(saltHex);
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    PBKDF2_HASH_BYTES * 8 // 256 bits = 32 bytes
  );
  return bufferToHex(derivedBits);
}

export async function computeUserFingerprint(passwordHashHex, saltHex) {
  const enc = new TextEncoder();
  const data = enc.encode(`${passwordHashHex.toLowerCase()}:${saltHex.toLowerCase()}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return bufferToHex(digest);
}

export async function signHmacSha256(dataStr, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(dataStr));
  return base64UrlEncode(new Uint8Array(sig));
}

export async function verifyHmacSha256(dataStr, sigB64Url, secret) {
  try {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const sigBytes = base64UrlDecode(sigB64Url);
    return await crypto.subtle.verify("HMAC", key, sigBytes, enc.encode(dataStr));
  } catch {
    return false;
  }
}

// ============================================================================
// Schema Validation for accounts.json
// ============================================================================

export function validateAccountsRegistry(data) {
  if (!data || typeof data !== "object") {
    return { valid: false, error: "Root must be an object" };
  }
  if (data.schema_version !== 1) {
    return { valid: false, error: "Unsupported schema_version; expected 1" };
  }
  if (!Array.isArray(data.users)) {
    return { valid: false, error: "users must be an array" };
  }
  if (data.users.length < 1 || data.users.length > MAX_USERS_COUNT) {
    return { valid: false, error: `users count must be between 1 and ${MAX_USERS_COUNT}` };
  }

  const seenUsernames = new Set();
  let hasActiveAdmin = false;

  for (let i = 0; i < data.users.length; i++) {
    const u = data.users[i];
    if (!u || typeof u !== "object") {
      return { valid: false, error: `User at index ${i} is invalid` };
    }
    if (typeof u.username !== "string" || !USERNAME_REGEX.test(u.username)) {
      return { valid: false, error: `Invalid username at index ${i}: ${u.username}` };
    }
    if (seenUsernames.has(u.username)) {
      return { valid: false, error: `Duplicate username: ${u.username}` };
    }
    seenUsernames.add(u.username);

    // full_name: non-empty string bounded to max 200 chars
    if (typeof u.full_name !== "string" || u.full_name.trim().length === 0 || u.full_name.length > 200) {
      return { valid: false, error: `Invalid full_name for ${u.username}; must be non-empty and max 200 chars` };
    }
    // unit: non-empty string bounded to max 200 chars
    if (typeof u.unit !== "string" || u.unit.trim().length === 0 || u.unit.length > 200) {
      return { valid: false, error: `Invalid unit for ${u.username}; must be non-empty and max 200 chars` };
    }
    if (u.role !== "admin" && u.role !== "officer") {
      return { valid: false, error: `Invalid role for ${u.username}; must be 'admin' or 'officer'` };
    }
    if (typeof u.active !== "boolean") {
      return { valid: false, error: `Invalid active boolean for ${u.username}` };
    }
    if (typeof u.salt !== "string" || !HEX_32_REGEX.test(u.salt)) {
      return { valid: false, error: `Invalid salt for ${u.username}; must be 32 hex chars (16 bytes)` };
    }
    if (typeof u.password_hash !== "string" || !HEX_64_REGEX.test(u.password_hash)) {
      return { valid: false, error: `Invalid password_hash for ${u.username}; must be 64 hex chars (32 bytes)` };
    }
    if (u.iterations !== PBKDF2_ITERATIONS) {
      return { valid: false, error: `Invalid iterations for ${u.username}; must be exactly ${PBKDF2_ITERATIONS}` };
    }

    if (u.role === "admin" && u.active === true) {
      hasActiveAdmin = true;
    }
  }

  if (!hasActiveAdmin) {
    return { valid: false, error: "Registry must contain at least one active admin user" };
  }

  return { valid: true, users: data.users };
}

// ============================================================================
// Streaming Helpers & GitHub Private Registry Loader
// ============================================================================

export async function readStreamBoundedText(body, maxBytes, timeoutMs = 8000) {
  if (!body) return "";

  const controller = new AbortController();
  let timeoutId = null;

  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      controller.abort("TIMEOUT");
      const err = new Error("Stream read timed out");
      err.status = 408;
      err.name = "TimeoutError";
      reject(err);
    }, timeoutMs);
  });

  const readPromise = (async () => {
    if (typeof body.getReader === "function") {
      const reader = body.getReader();
      const decoder = new TextDecoder("utf-8", { fatal: true });
      let totalBytes = 0;
      let text = "";

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          totalBytes += value.byteLength;
          if (totalBytes > maxBytes) {
            try { await reader.cancel("OVERFLOW"); } catch {}
            controller.abort("OVERFLOW");
            const err = new Error(`Payload exceeds maximum size of ${maxBytes} bytes`);
            err.status = maxBytes <= 4096 ? 413 : 503;
            err.code = "OVERFLOW";
            throw err;
          }
          text += decoder.decode(value, { stream: true });
        }
        text += decoder.decode();
        return text;
      } catch (err) {
        try { await reader.cancel(err); } catch {}
        throw err;
      }
    } else if (typeof body.arrayBuffer === "function") {
      const buf = await body.arrayBuffer();
      if (buf.byteLength > maxBytes) {
        const err = new Error(`Payload exceeds maximum size of ${maxBytes} bytes`);
        err.status = maxBytes <= 4096 ? 413 : 503;
        err.code = "OVERFLOW";
        throw err;
      }
      return new TextDecoder("utf-8", { fatal: true }).decode(buf);
    } else if (typeof body.text === "function") {
      const text = await body.text();
      const bytes = new TextEncoder().encode(text);
      if (bytes.byteLength > maxBytes) {
        const err = new Error(`Payload exceeds maximum size of ${maxBytes} bytes`);
        err.status = maxBytes <= 4096 ? 413 : 503;
        err.code = "OVERFLOW";
        throw err;
      }
      return text;
    }
    return "";
  })();

  try {
    return await Promise.race([readPromise, timeoutPromise]);
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

export async function fetchWithLimit(fetchImpl, urlStr, options, maxBytes = MAX_REGISTRY_BYTES, timeoutMs = 8000) {
  const url = new URL(urlStr);
  if (url.hostname !== GITHUB_HOST) {
    const err = new Error(`Host rejected: only ${GITHUB_HOST} is permitted`);
    err.status = 503;
    throw err;
  }

  const controller = new AbortController();
  let timeoutId = null;

  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      controller.abort("TIMEOUT");
      const err = new Error("GitHub request timed out after 8s");
      err.status = 503;
      err.name = "TimeoutError";
      reject(err);
    }, timeoutMs);
  });

  const fetchPromise = (async () => {
    const reqOptions = {
      ...options,
      signal: controller.signal,
      redirect: "error" // Strict: redirects are forbidden
    };

    const response = await fetchImpl(urlStr, reqOptions);
    if (!response || !response.ok) {
      const status = response ? response.status : 503;
      const err = new Error(`GitHub request failed with HTTP ${status}`);
      err.status = 503;
      throw err;
    }

    const cl = response.headers?.get?.("content-length");
    if (cl && parseInt(cl, 10) > maxBytes) {
      controller.abort("OVERFLOW");
      const err = new Error(`Response body exceeds maximum size of ${maxBytes} bytes`);
      err.status = 503;
      throw err;
    }

    let bodyText = "";
    if (response.body && typeof response.body.getReader === "function") {
      const reader = response.body.getReader();
      const decoder = new TextDecoder("utf-8", { fatal: true });
      let totalBytes = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          totalBytes += value.byteLength;
          if (totalBytes > maxBytes) {
            try { await reader.cancel("OVERFLOW"); } catch {}
            controller.abort("OVERFLOW");
            const err = new Error(`Response body exceeds maximum size of ${maxBytes} bytes`);
            err.status = 503;
            throw err;
          }
          bodyText += decoder.decode(value, { stream: true });
        }
        bodyText += decoder.decode();
      } catch (readErr) {
        try { await reader.cancel(readErr); } catch {}
        throw readErr;
      }
    } else {
      const text = await response.text();
      const byteLen = new TextEncoder().encode(text).byteLength;
      if (byteLen > maxBytes) {
        controller.abort("OVERFLOW");
        const err = new Error(`Response body exceeds maximum size of ${maxBytes} bytes`);
        err.status = 503;
        throw err;
      }
      bodyText = text;
    }

    try {
      return JSON.parse(bodyText);
    } catch {
      const err = new Error("Invalid JSON in GitHub response");
      err.status = 503;
      throw err;
    }
  })();

  try {
    return await Promise.race([fetchPromise, timeoutPromise]);
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

export async function loadAccountsRegistry(env, fetchImpl, now, cacheInstance) {
  const repo = env.GITHUB_REPOSITORY;
  const token = env.GITHUB_TOKEN;
  const sessionSecret = env.SESSION_SECRET;
  const branch = env.AUTH_BRANCH || DEFAULT_AUTH_BRANCH;

  if (
    !repo ||
    typeof repo !== "string" ||
    !REPO_FORMAT_REGEX.test(repo) ||
    !token ||
    typeof token !== "string" ||
    token.trim().length === 0 ||
    !sessionSecret ||
    typeof sessionSecret !== "string" ||
    sessionSecret.length < 32
  ) {
    const err = new Error("Service configuration incomplete or invalid");
    err.code = "CONFIG_INVALID";
    err.status = 503;
    throw err;
  }

  // Registry cache key strictly includes token and SESSION_SECRET credentials (never logged)
  const cacheKey = `${repo}:${branch}:${token}:${sessionSecret}`;
  const nowMs = now();

  // Check valid cache entry
  const cached = cacheInstance.get(cacheKey);
  if (cached && nowMs < cached.expiresAt) {
    return cached.users;
  }

  // Cache miss or expired: fetch fresh data from GitHub.
  // Note: "no stale on fail" - do not use previous cache if fetch fails!
  try {
    const commonHeaders = {
      Authorization: `Bearer ${token}`,
      "User-Agent": "cskh-auth-worker",
      Accept: "application/vnd.github+json"
    };

    // Step 1: Verify GitHub repository is strictly PRIVATE
    const repoUrl = `https://${GITHUB_HOST}/repos/${repo}`;
    const repoMeta = await fetchWithLimit(
      fetchImpl,
      repoUrl,
      {
        method: "GET",
        headers: commonHeaders
      },
      MAX_REGISTRY_BYTES,
      8000
    );

    if (repoMeta.private !== true) {
      const privErr = new Error("GitHub repository must be private");
      privErr.status = 503;
      throw privErr;
    }

    // Step 2: Fetch raw content of accounts.json
    const accountsUrl = `https://${GITHUB_HOST}/repos/${repo}/contents/accounts.json?ref=${encodeURIComponent(branch)}`;
    const accountsHeaders = {
      ...commonHeaders,
      Accept: "application/vnd.github.raw+json"
    };

    const accountsData = await fetchWithLimit(
      fetchImpl,
      accountsUrl,
      {
        method: "GET",
        headers: accountsHeaders
      },
      MAX_REGISTRY_BYTES,
      8000
    );

    const validation = validateAccountsRegistry(accountsData);
    if (!validation.valid) {
      const schemaErr = new Error(`Invalid accounts schema: ${validation.error}`);
      schemaErr.status = 503;
      throw schemaErr;
    }

    // Cache successful registry for max 60 seconds
    cacheInstance.set(cacheKey, {
      users: validation.users,
      expiresAt: nowMs + REGISTRY_CACHE_TTL_MS
    });

    return validation.users;
  } catch (err) {
    // Ensure expired or invalid cache is evicted so stale is never served
    cacheInstance.delete(cacheKey);
    if (!err.status) err.status = 503;
    throw err;
  }
}

// ============================================================================
// Session Token & Cookie Handling
// ============================================================================

export function parseCookies(request) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = new Map();
  const pairs = cookieHeader.split(";");
  for (let i = 0; i < pairs.length; i++) {
    const part = pairs[i].trim();
    if (!part) continue;
    const eqIdx = part.indexOf("=");
    if (eqIdx !== -1) {
      const key = part.slice(0, eqIdx).trim();
      const val = part.slice(eqIdx + 1).trim();
      cookies.set(key, val);
    }
  }
  return cookies;
}

export async function createSessionToken(user, secret, nowSeconds) {
  const exp = nowSeconds + SESSION_TTL_SECONDS;
  const fingerprint = await computeUserFingerprint(user.password_hash, user.salt);
  const payload = {
    sub: user.username,
    exp,
    fingerprint
  };
  const enc = new TextEncoder();
  const payloadStr = JSON.stringify(payload);
  const payloadB64 = base64UrlEncode(enc.encode(payloadStr));
  const sigB64 = await signHmacSha256(payloadB64, secret);
  return `${payloadB64}.${sigB64}`;
}

export function buildSetCookieHeader(token) {
  return `${SESSION_COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`;
}

export function buildClearCookieHeader() {
  return `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

export async function authenticateSession(request, env, fetchImpl, now, cacheInstance) {
  const cookies = parseCookies(request);
  const token = cookies.get(SESSION_COOKIE_NAME);
  if (!token) {
    return { authenticated: false, status: 401, error: "Missing session cookie" };
  }

  const dotIdx = token.indexOf(".");
  if (dotIdx === -1) {
    return { authenticated: false, status: 401, error: "Malformed session token" };
  }

  const payloadB64 = token.slice(0, dotIdx);
  const sigB64 = token.slice(dotIdx + 1);

  const isValidSig = await verifyHmacSha256(payloadB64, sigB64, env.SESSION_SECRET);
  if (!isValidSig) {
    return { authenticated: false, status: 401, error: "Invalid token signature" };
  }

  let payload;
  try {
    const payloadBytes = base64UrlDecode(payloadB64);
    payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    return { authenticated: false, status: 401, error: "Invalid token payload" };
  }

  const nowSeconds = Math.floor(now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp <= nowSeconds) {
    return { authenticated: false, status: 401, error: "Session token expired" };
  }

  if (typeof payload.sub !== "string" || typeof payload.fingerprint !== "string") {
    return { authenticated: false, status: 401, error: "Malformed payload claims" };
  }

  // Load registry to verify user existence, active status, and password fingerprint
  let users;
  try {
    users = await loadAccountsRegistry(env, fetchImpl, now, cacheInstance);
  } catch (err) {
    return {
      authenticated: false,
      status: err.status || 503,
      error: "Authentication service unavailable"
    };
  }

  const user = users.find(u => u.username === payload.sub);
  if (!user) {
    return { authenticated: false, status: 401, error: "User not found" };
  }
  if (!user.active) {
    return { authenticated: false, status: 401, error: "User deactivated" };
  }

  // Cryptographic fingerprint verification (reject password changes or rotated salt)
  const currentFingerprint = await computeUserFingerprint(user.password_hash, user.salt);
  if (!timingSafeEqual(payload.fingerprint, currentFingerprint)) {
    return { authenticated: false, status: 401, error: "Session revoked: credentials changed" };
  }

  // Return sanitized identity derived strictly from authoritative registry
  return {
    authenticated: true,
    user: {
      username: user.username,
      full_name: user.full_name,
      unit: user.unit,
      role: user.role
    }
  };
}

// ============================================================================
// Rate Limiting Enforcement
// ============================================================================

export function getClientIp(request) {
  // Trust cf-connecting-ip ONLY; never use attacker-supplied x-forwarded-for
  const cfIp = request.headers.get("cf-connecting-ip");
  if (cfIp && cfIp.trim().length > 0) {
    return cfIp.trim();
  }
  // Deterministic fallback for test fixtures / local tests without CF proxy
  return "127.0.0.1";
}

export async function checkRateLimit(request, env, username) {
  if (!env.AUTH_RATE_LIMIT || typeof env.AUTH_RATE_LIMIT.limit !== "function") {
    return { ok: false, error: "RATE_LIMIT_UNAVAILABLE", status: 503 };
  }

  try {
    const ip = getClientIp(request);
    const userKey = `login_user:${ip}:${username.toLowerCase()}`;
    const ipKey = `login_ip:${ip}`;

    const [resUser, resIp] = await Promise.all([
      env.AUTH_RATE_LIMIT.limit({ key: userKey }),
      env.AUTH_RATE_LIMIT.limit({ key: ipKey })
    ]);

    // Check for undefined or malformed result -> MUST fail 503
    if (
      !resUser ||
      typeof resUser !== "object" ||
      typeof resUser.success !== "boolean" ||
      !resIp ||
      typeof resIp !== "object" ||
      typeof resIp.success !== "boolean"
    ) {
      return { ok: false, error: "RATE_LIMIT_UNAVAILABLE", status: 503 };
    }

    if (!resUser.success || !resIp.success) {
      return { ok: false, error: "RATE_LIMITED", status: 429 };
    }

    return { ok: true };
  } catch {
    // Exceptions MUST fail 503, never permit!
    return { ok: false, error: "RATE_LIMIT_UNAVAILABLE", status: 503 };
  }
}

// ============================================================================
// Path Normalization & Security Filter
// ============================================================================

export function normalizePathname(rawUrlStr) {
  try {
    // Check for encoded path traversal sequences in raw URL
    if (/%2e%2e/i.test(rawUrlStr) || /%5c/i.test(rawUrlStr) || /%252e/i.test(rawUrlStr)) {
      return null;
    }
    const url = new URL(rawUrlStr);
    let decoded = decodeURIComponent(url.pathname);
    // Standardize slashes
    decoded = decoded.replace(/\\/g, "/");
    // Reject path traversal attempts or double slashes
    if (decoded.includes("..") || decoded.includes("//")) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

export function isForbiddenAssetPath(pathname) {
  // Check exact denied files
  if (
    pathname === "/auth-worker.mjs" ||
    pathname === "/wrangler.json" ||
    pathname === "/accounts.json" ||
    pathname === "/.assetsignore" ||
    pathname.startsWith("/secrets")
  ) {
    return true;
  }
  // Check pattern matches
  if (/^\/accounts.*\.json$/i.test(pathname)) return true;
  if (/^\/\.git(\/.*)?$/i.test(pathname)) return true;
  if (/^\/node_modules(\/.*)?$/i.test(pathname)) return true;
  // Deny hidden files
  if (/\/\.[^/]+/.test(pathname)) return true;

  return false;
}

export function isScalar(val) {
  return (
    typeof val === "string" ||
    typeof val === "number" ||
    typeof val === "boolean" ||
    val === null
  );
}

export function sanitizeOverview(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Invalid overview data");
  }
  const result = {};
  for (const key of Object.keys(data)) {
    if (OVERVIEW_WHITELIST.has(key)) {
      const val = data[key];
      if (isScalar(val)) {
        result[key] = val;
      }
    }
  }
  return result;
}

export function sanitizeStationsSummary(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Invalid stations summary data");
  }
  const result = {};
  for (const key of Object.keys(data)) {
    if (STATION_ROOT_WHITELIST.has(key)) {
      const val = data[key];
      if (isScalar(val)) {
        result[key] = val;
      }
    }
  }

  if (!Array.isArray(data.stations)) {
    throw new Error("Missing stations array");
  }

  result.stations = data.stations.map(st => {
    if (!st || typeof st !== "object" || Array.isArray(st)) return {};
    const sanitized = {};
    for (const key of Object.keys(st)) {
      if (STATION_SUMMARY_WHITELIST.has(key)) {
        const val = st[key];
        // Enforce scalar only; do not allow objects or arrays containing private details!
        if (isScalar(val)) {
          sanitized[key] = val;
        }
      }
    }
    return sanitized;
  });

  return result;
}

// ============================================================================
// Handler Factory (Dependency Injection for deterministic unit tests)
// ============================================================================

export function createHandler(options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const now = options.now || (() => Date.now());
  const registryCache = new Map();

  // Internal dispatch logic
  async function internalFetch(request, env, ctx) {
    const url = new URL(request.url);
    const normalizedPath = normalizePathname(request.url);

    if (!normalizedPath) {
      return new Response(JSON.stringify({ error: "Invalid path or traversal attempt" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    // 1. Explicitly Denied Asset & Secret Paths -> 404
    if (isForbiddenAssetPath(normalizedPath)) {
      return new Response(JSON.stringify({ error: "Not Found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" }
      });
    }

    // 2. Authentication API Endpoints (/api/auth/...)
    if (normalizedPath === "/api/auth/login") {
      if (request.method !== "POST") {
        return new Response(JSON.stringify({ error: "Method Not Allowed" }), {
          status: 405,
          headers: { "Content-Type": "application/json" }
        });
      }

      // Enforce same-origin check
      const origin = request.headers.get("Origin");
      if (!origin || origin !== url.origin) {
        return new Response(JSON.stringify({ error: "Forbidden: Origin mismatch" }), {
          status: 403,
          headers: { "Content-Type": "application/json" }
        });
      }

      // Enforce Content-Type
      const ct = request.headers.get("Content-Type") || "";
      if (!ct.toLowerCase().startsWith("application/json")) {
        return new Response(JSON.stringify({ error: "Unsupported Media Type: application/json required" }), {
          status: 415,
          headers: { "Content-Type": "application/json" }
        });
      }

      // Enforce Content-Length <= 4096
      const cl = request.headers.get("Content-Length");
      if (cl && parseInt(cl, 10) > MAX_LOGIN_BODY_BYTES) {
        return new Response(JSON.stringify({ error: "Payload Too Large: maximum 4096 bytes" }), {
          status: 413,
          headers: { "Content-Type": "application/json" }
        });
      }

      // Stream read body up to 4096 bytes with timeout
      let bodyText = "";
      try {
        bodyText = await readStreamBoundedText(request.body || request, MAX_LOGIN_BODY_BYTES, 8000);
      } catch (readErr) {
        if (readErr.status === 413 || readErr.code === "OVERFLOW") {
          return new Response(JSON.stringify({ error: "Payload Too Large: maximum 4096 bytes" }), {
            status: 413,
            headers: { "Content-Type": "application/json" }
          });
        }
        return new Response(JSON.stringify({ error: "Request timeout or read error" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }

      let loginPayload;
      try {
        loginPayload = JSON.parse(bodyText);
      } catch {
        return new Response(JSON.stringify({ error: "Invalid JSON format" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }

      // null or array JSON -> 400 not throw!
      if (!loginPayload || typeof loginPayload !== "object" || Array.isArray(loginPayload)) {
        return new Response(JSON.stringify({ error: "Invalid JSON format: object required" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }

      const username = typeof loginPayload.username === "string" ? loginPayload.username.trim() : "";
      const password = typeof loginPayload.password === "string" ? loginPayload.password : "";

      if (!username || !password) {
        return new Response(JSON.stringify({ error: "Tên đăng nhập hoặc mật khẩu không chính xác" }), {
          status: 401,
          headers: { "Content-Type": "application/json" }
        });
      }

      // Rate limiting check: mandatory
      const rlResult = await checkRateLimit(request, env, username);
      if (!rlResult.ok) {
        if (rlResult.status === 429) {
          return new Response(JSON.stringify({ error: "Quá nhiều yêu cầu đăng nhập. Vui lòng thử lại sau." }), {
            status: 429,
            headers: { "Content-Type": "application/json" }
          });
        }
        return new Response(JSON.stringify({ error: "Rate limiting configuration error" }), {
          status: 503,
          headers: { "Content-Type": "application/json" }
        });
      }

      // Load registry
      let users;
      try {
        users = await loadAccountsRegistry(env, fetchImpl, now, registryCache);
      } catch {
        return new Response(JSON.stringify({ error: "Dịch vụ xác thực tạm thời không khả dụng" }), {
          status: 503,
          headers: { "Content-Type": "application/json" }
        });
      }

      const user = users.find(u => u.username === username.toLowerCase());
      if (!user || !user.active) {
        // Dummy calculation to maintain consistent response time against timing attacks
        await computePbkdf2Hash(password, "0123456789abcdef0123456789abcdef", PBKDF2_ITERATIONS);
        return new Response(JSON.stringify({ ok: false, error: "Tên đăng nhập hoặc mật khẩu không chính xác" }), {
          status: 401,
          headers: { "Content-Type": "application/json" }
        });
      }

      const passwordMatch = timingSafeEqual(
        await computePbkdf2Hash(password, user.salt, PBKDF2_ITERATIONS),
        user.password_hash.toLowerCase()
      );

      if (!passwordMatch) {
        return new Response(JSON.stringify({ ok: false, error: "Tên đăng nhập hoặc mật khẩu không chính xác" }), {
          status: 401,
          headers: { "Content-Type": "application/json" }
        });
      }

      const nowSeconds = Math.floor(now() / 1000);
      const token = await createSessionToken(user, env.SESSION_SECRET, nowSeconds);
      const setCookieHeader = buildSetCookieHeader(token);

      return new Response(
        JSON.stringify({
          ok: true,
          user: {
            username: user.username,
            full_name: user.full_name,
            unit: user.unit,
            role: user.role
          }
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie": setCookieHeader
          }
        }
      );
    }

    if (normalizedPath === "/api/auth/me") {
      if (request.method !== "GET") {
        return new Response(JSON.stringify({ error: "Method Not Allowed" }), {
          status: 405,
          headers: { "Content-Type": "application/json" }
        });
      }

      const auth = await authenticateSession(request, env, fetchImpl, now, registryCache);
      if (!auth.authenticated) {
        return new Response(JSON.stringify({ ok: false, error: auth.error }), {
          status: auth.status || 401,
          headers: { "Content-Type": "application/json" }
        });
      }

      return new Response(
        JSON.stringify({
          ok: true,
          user: auth.user
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    if (normalizedPath === "/api/auth/logout") {
      if (request.method !== "POST") {
        return new Response(JSON.stringify({ error: "Method Not Allowed" }), {
          status: 405,
          headers: { "Content-Type": "application/json" }
        });
      }

      const origin = request.headers.get("Origin");
      if (!origin || origin !== url.origin) {
        return new Response(JSON.stringify({ error: "Forbidden: Origin mismatch" }), {
          status: 403,
          headers: { "Content-Type": "application/json" }
        });
      }

      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": buildClearCookieHeader()
        }
      });
    }

    // No web account creation, password reset, or provision endpoints
    if (normalizedPath.startsWith("/api/")) {
      return new Response(JSON.stringify({ error: "Not Found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" }
      });
    }

    // 3. Protected Station Partition Routes (/data/stations/... and /static/data/stations/...)
    const stationMatch =
      normalizedPath.match(PROTECTED_STATION_REGEX) ||
      normalizedPath.match(PROTECTED_STATION_ALIAS_REGEX);

    if (stationMatch) {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return new Response(JSON.stringify({ error: "Method Not Allowed" }), {
          status: 405,
          headers: { "Content-Type": "application/json" }
        });
      }

      const auth = await authenticateSession(request, env, fetchImpl, now, registryCache);
      if (!auth.authenticated) {
        // Unauthenticated station requests return 401 without real JSON data
        return new Response(
          request.method === "HEAD"
            ? null
            : JSON.stringify({
                error: "Unauthorized: Vui lòng đăng nhập để xem thông tin chi tiết trạm biến áp."
              }),
          {
            status: auth.status || 401,
            headers: { "Content-Type": "application/json" }
          }
        );
      }

      // Authenticated: fetch underlying static partition from ASSETS binding
      if (!env.ASSETS || typeof env.ASSETS.fetch !== "function") {
        return new Response(JSON.stringify({ error: "Asset storage unavailable" }), {
          status: 503,
          headers: { "Content-Type": "application/json" }
        });
      }

      // If accessed via /static/data/stations alias, normalize target URL to /data/stations/...
      let assetUrl = request.url;
      if (normalizedPath.startsWith("/static/data/stations/")) {
        const stationId = stationMatch[1];
        const newUrl = new URL(request.url);
        newUrl.pathname = `/data/stations/${stationId}.json`;
        assetUrl = newUrl.toString();
      }

      const assetResponse = await env.ASSETS.fetch(new Request(assetUrl, request));
      if (request.method === "HEAD" && assetResponse.body) {
        return new Response(null, {
          status: assetResponse.status,
          statusText: assetResponse.statusText,
          headers: assetResponse.headers
        });
      }
      return assetResponse;
    }

    // 4. Public Static Allowlist
    if (PUBLIC_STATIC_PATHS.has(normalizedPath)) {
      if (!["GET", "HEAD"].includes(request.method)) {
        return new Response(JSON.stringify({ error: "Method Not Allowed" }), {
          status: 405,
          headers: { "Content-Type": "application/json" }
        });
      }

      if (!env.ASSETS || typeof env.ASSETS.fetch !== "function") {
        return new Response(JSON.stringify({ error: "Asset storage unavailable" }), {
          status: 503,
          headers: { "Content-Type": "application/json" }
        });
      }

      // /data/overview.json: Whitelist overview summary fields only, reject invalid with 503 (no raw fallback)
      if (normalizedPath === "/data/overview.json") {
        // Canonical internal GET stripping Range, If*, and client headers
        const canonicalUrl = new URL(normalizedPath, url.origin).toString();
        const canonicalReq = new Request(canonicalUrl, {
          method: "GET",
          headers: {
            Accept: "application/json"
          }
        });

        const assetResponse = await env.ASSETS.fetch(canonicalReq);
        if (!assetResponse || assetResponse.status !== 200) {
          // Reject ALL non-200 with worker generic error; NO passthrough raw body!
          return new Response(JSON.stringify({ error: "Overview asset unavailable" }), {
            status: 503,
            headers: { "Content-Type": "application/json" }
          });
        }

        try {
          const rawData = await assetResponse.json();
          const sanitized = sanitizeOverview(rawData);
          const bodyStr = JSON.stringify(sanitized);

          return new Response(request.method === "HEAD" ? null : bodyStr, {
            status: 200,
            headers: {
              "Content-Type": "application/json; charset=utf-8",
              "Content-Length": String(new TextEncoder().encode(bodyStr).byteLength)
            }
          });
        } catch {
          return new Response(JSON.stringify({ error: "Failed to parse overview summary" }), {
            status: 503,
            headers: { "Content-Type": "application/json" }
          });
        }
      }

      // /data/stations.json: Whitelist summary fields to redact arbitrary sensitive fields
      if (normalizedPath === "/data/stations.json") {
        // Canonical internal GET stripping Range, If*, and client headers
        const canonicalUrl = new URL(normalizedPath, url.origin).toString();
        const canonicalReq = new Request(canonicalUrl, {
          method: "GET",
          headers: {
            Accept: "application/json"
          }
        });

        const assetResponse = await env.ASSETS.fetch(canonicalReq);
        if (!assetResponse || assetResponse.status !== 200) {
          // Reject ALL non-200 with worker generic error; NO passthrough raw body!
          return new Response(JSON.stringify({ error: "Stations asset unavailable" }), {
            status: 503,
            headers: { "Content-Type": "application/json" }
          });
        }

        try {
          const rawData = await assetResponse.json();
          const sanitizedData = sanitizeStationsSummary(rawData);
          const bodyStr = JSON.stringify(sanitizedData);

          return new Response(request.method === "HEAD" ? null : bodyStr, {
            status: 200,
            headers: {
              "Content-Type": "application/json; charset=utf-8",
              "Content-Length": String(new TextEncoder().encode(bodyStr).byteLength)
            }
          });
        } catch {
          return new Response(JSON.stringify({ error: "Failed to parse stations summary" }), {
            status: 503,
            headers: { "Content-Type": "application/json" }
          });
        }
      }

      // All other public static assets: pass through to ASSETS
      return env.ASSETS.fetch(request);
    }

    // 5. Deny all other asset paths -> 404
    return new Response(JSON.stringify({ error: "Not Found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" }
    });
  }

  // Outer Wrapper:
  // 1. Catches all outer errors -> generic 503 (never leak secrets or raw error messages)
  // 2. Enforces Cache-Control: no-store, no-cache, must-revalidate, private on all responses
  return {
    async fetch(request, env, ctx) {
      try {
        const response = await internalFetch(request, env, ctx);
        const headers = new Headers(response.headers);
        headers.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
        headers.set("Pragma", "no-cache");

        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers
        });
      } catch {
        return new Response(JSON.stringify({ error: "Service temporarily unavailable" }), {
          status: 503,
          headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            Pragma: "no-cache"
          }
        });
      }
    }
  };
}

export default createHandler();
