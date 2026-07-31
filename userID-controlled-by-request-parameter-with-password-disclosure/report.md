# Vulnerability Report: Account Takeover via IDOR with Password Disclosure in Account Page

**Severity:** High  
**CVSS Score:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)  
**Date:** 2026-07-31  
**Target:** variableSub.web-security-academy.net  

## Executive Summary
An Insecure Direct Object Reference (IDOR) vulnerability was identified in the account page of the application,
combined with a password disclosure issue in the HTML response.
The application uses a user-controlled `id` parameter in the query string to determine which account page to render,
with no verification that the requesting session matches the requested user.
Additionally, the account page pre-fills the password change form with the user's current plaintext password pulled directly from the database.
An attacker with any valid account can request any other user's account page by changing the `id` parameter,
and retrieve their plaintext password from the HTML response — leading to full account takeover with no further exploitation required.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | Insecure Direct Object Reference (IDOR) + Password Disclosure in HTML Response |
| Endpoint | `GET /my-account?id={username}` |
| Method | GET |
| Protection | None — server only verifies authentication, not authorization |
| Bypass | Replacing the `id` parameter value with any other username |
| Requirement | Any authenticated session on the platform |
| User Interaction | Not required |

## Steps to Reproduce
1. Log in with valid credentials (`wiener:peter`) — a session cookie is issued.
2. Navigate to `/my-account?id=wiener` and inspect the HTML response.
3. Observe that the password change form contains a pre-filled `type=password` input with the current user's plaintext password in the `value` attribute.
4. Send the request to a replay tool (e.g., Burp Repeater).
5. Change the `id` parameter from `wiener` to `administrator`.
6. Send the modified request — observe a `200 OK` response with the administrator's account page, including their plaintext password in the HTML.
7. Log in using `administrator` and the recovered password.
8. Navigate to the admin panel and delete the target user (`carlos`) — full account takeover confirmed.

## Proof of Concept
```http
GET /my-account?id=administrator HTTP/2
Host: variableSub.web-security-academy.net
Cookie: session=bHQPGdhmp5MF4186HSOWIHDJDAgtv1UR
```

**Response (truncated):**
```html
<p>Your username is: administrator</p>
...
<input required type=password name=password value='57ll3u25jetho8hn0871'/>
```

## Impact
Any authenticated user can access any other user's account page by modifying the `id` parameter in the URL.
Because the application also discloses the target user's plaintext password in the HTML response,
this vulnerability directly leads to credential theft and full account takeover — requiring no brute-forcing, no special tooling, and no victim interaction.

This can lead to:
- Full account takeover of any user on the platform, including administrators
- Exposure of plaintext credentials that likely work on other platforms due to password reuse
- Unauthorized access to all personal data and functionality tied to any compromised account
- Privilege escalation to administrator level, enabling destructive actions such as deleting other users

## Remediation
- Authorization must be enforced server-side on every account page request — the server must verify that the authenticated session matches the requested `id` before serving any data. Checking that a user is logged in is not sufficient; the server must also confirm they are allowed to access that specific resource.
- Passwords must never appear in HTTP responses under any circumstances. If a password change form requires pre-filling, use a placeholder or prompt the user to re-enter their current password — never pull the actual value from the database into the HTML.
- Account pages should be served based on session identity alone, with no user-controlled parameter involved in determining what data to return. If a parameter is needed for routing, it must be validated against the session server-side on every request.
- Conduct a full audit of other user-specific endpoints for similar missing authorization checks.

## References
- OWASP: Broken Access Control (A01:2021)
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-256: Plaintext Storage of a Password
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- PortSwigger: Insecure Direct Object References (IDOR)