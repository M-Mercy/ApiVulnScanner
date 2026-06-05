# OWASP API Security Top 10 — APIScan Mapping

This document shows which APIScan checks map to each OWASP API Security Top 10 (2023 Edition) category, and explains the attack scenarios relevant to Kenyan fintech APIs.

---

## API1:2023 — Broken Object Level Authorization (BOLA)

**What it is:** APIs expose endpoints that handle object identifiers (e.g. account IDs, transaction IDs). The server doesn't properly verify whether the requesting user actually has access to the requested object.

**Kenyan fintech example:**
```
GET /api/v1/mpesa/transactions/12345
Authorization: Bearer <alice's token>

→ Returns transactions belonging to user account 12346 (Bob's account)
```

**APIScan checks:** `bola-idor-detection` — detects sequential numeric IDs in paths and tests whether incrementing/decrementing the ID returns data.

**Severity:** HIGH — CVSS 7.5

---

## API2:2023 — Broken Authentication

**What it is:** Authentication mechanisms are incorrectly implemented, allowing attackers to compromise tokens or bypass authentication entirely.

**Kenyan fintech example:**
- Endpoint returns 200 without any `Authorization` header
- Expired JWT tokens are still accepted
- `{"alg":"none"}` JWT tokens are accepted (signature bypass)

**APIScan checks:**
- `missing-authentication` — tests endpoints without any credentials
- `invalid-token-acceptance` — tests with malformed/expired tokens

**Severity:** CRITICAL (token bypass) / HIGH (missing auth)

---

## API3:2023 — Broken Object Property Level Authorization

**What it is:** The API returns more object properties than the client needs, including sensitive fields. Also known as "Excessive Data Exposure."

**Kenyan fintech example:**
```json
GET /api/v1/users/profile
→ {
    "name": "Alice",
    "email": "alice@example.com",
    "password_hash": "$2b$10$...",   ← Should never be returned
    "api_key": "sk_live_...",         ← Critical exposure
    "internal_user_id": 12345         ← Enables BOLA enumeration
}
```

**APIScan checks:** `excessive-data-exposure` — scans response JSON for sensitive field names.

**Severity:** CRITICAL (secrets/credentials) / HIGH (tokens/API keys)

---

## API4:2023 — Unrestricted Resource Consumption

**What it is:** No rate limiting allows automated abuse of API resources.

**Kenyan fintech example:**
- No rate limit on `/api/v1/auth/login` → credential stuffing
- No rate limit on `/api/v1/payments/send` → automated payment attempts
- No rate limit on OTP verification → brute force OTP codes

**APIScan checks:** `rate-limiting-absent` — sends burst requests and checks for 429 responses or rate-limit headers.

**Severity:** HIGH (auth endpoints) / MEDIUM (general endpoints)

---

## API5:2023 — Broken Function Level Authorization

**What it is:** Complex access control policies result in lower-privileged users being able to access admin functions.

**Kenyan fintech example:**
```
POST /api/v1/admin/users/12345/delete
Authorization: Bearer <regular_user_token>
→ 200 OK  ← Regular user can delete any account
```

**APIScan checks:** `bfla-detection` *(Phase 2)* — tests admin endpoints with non-admin credentials.

---

## API6:2023 — Unrestricted Access to Sensitive Business Flows

**What it is:** Legitimate API flows can be abused at scale.

**Kenyan fintech example:**
- Automated voucher code exhaustion
- Gift card brute forcing
- Mass account creation for fraud

**APIScan checks:** *(Phase 3 — requires business logic understanding)*

---

## API7:2023 — Server Side Request Forgery (SSRF)

**What it is:** APIs accept URLs as input and fetch remote resources without validation.

**Kenyan fintech example:**
```
POST /api/v1/webhook/register
{ "callback_url": "http://169.254.169.254/latest/meta-data/" }
→ Returns AWS metadata (credential theft)
```

**APIScan checks:** *(Phase 2)* — tests URL parameters with SSRF payloads. Note: APIScan's safe mode prevents it from being used as an SSRF tool itself.

---

## API8:2023 — Security Misconfiguration

**What it is:** Missing security hardening, open cloud storage, unnecessary HTTP methods enabled, verbose error messages.

**Kenyan fintech example:**
- `X-Powered-By: Laravel 9.0` reveals exact framework version
- Stack traces in error responses reveal database schema
- `Access-Control-Allow-Origin: *` allows cross-site API calls

**APIScan checks:**
- `security-headers` — checks for missing/misconfigured response headers and CORS
- `error-information-disclosure` — detects stack traces and internal paths in responses

**Severity:** MEDIUM to HIGH

---

## API9:2023 — Improper Inventory Management

**What it is:** Outdated, undocumented, or debug API endpoints exposed in production.

**Kenyan fintech example:**
- `/api/v1/debug/users` endpoint forgotten in production
- `/api/v2-beta/payments` endpoint with weaker security than v1
- Swagger UI enabled in production exposing full API spec

**APIScan checks:** *(Phase 3)* — endpoint discovery for common debug/admin paths.

---

## API10:2023 — Unsafe Consumption of APIs

**What it is:** The API trusts data received from third-party APIs without validation, leading to injection or data integrity issues.

**Kenyan fintech example:**
- Payment processor returns a webhook payload → API stores it without validation → stored XSS
- M-Pesa callback data inserted directly into database query → SQLi

**APIScan checks:** *(Phase 4)* — tests webhook endpoint handling.

---

## CVSS Score Guidance

APIScan uses CVSS v3.1-inspired scoring:

| Score Range | Severity | Example |
|-------------|----------|---------|
| 9.0 – 10.0 | CRITICAL | Unauthenticated access to financial data |
| 7.0 – 8.9 | HIGH | SQL injection, BOLA with auth |
| 4.0 – 6.9 | MEDIUM | Missing rate limiting, CORS misconfiguration |
| 0.1 – 3.9 | LOW | Missing non-critical headers, verbose errors |
| 0.0 | INFO | Technology disclosure, best practice gaps |

---

*References:*
- *OWASP API Security Project: https://owasp.org/API-Security/*
- *Kenya Computer Misuse and Cybercrimes Act 2018*
- *NIST NVD CVSS Calculator: https://nvd.nist.gov/vuln-metrics/cvss*
