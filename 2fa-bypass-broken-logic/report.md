# Vulnerability Report: Account Takeover via 2FA Broken Logic and OTP Brute-Force

**Severity:** Critical  
**CVSS Score:** 9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)  
**Date:** 2026-07-26  
**Target:** TARGET.web-security-academy.net  

## Executive Summary
A broken authentication vulnerability was identified in the 2FA verification flow of the application.
The application binds the OTP to a client-controlled cookie parameter (`verify=username`) rather than to the server-side session.
This allows an attacker to generate an OTP for any arbitrary user by simply changing the cookie value,
then brute-force the 4-digit code against the verification endpoint — which enforces no rate limiting.
The result is a zero-interaction, full account takeover requiring only the victim's username.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | Broken Authentication — 2FA Logic Flaw |
| Endpoint | `POST /login2` |
| Method | POST |
| Vulnerable Parameter | `verify` (Cookie) + `mfa-code` (POST body) |
| Protection | None (no rate limiting, no lockout) |
| OTP Space | 4-digit numeric (10,000 possible values) |
| User Interaction | Not required |

## Steps to Reproduce
1. Log in with valid credentials — observe the POST request to `/login` and the subsequent redirect to `/login2`.
2. Note that a `verify=<username>` cookie is set after the first login step.
3. In Burp Repeater, send a GET request to `/login2` with the cookie modified to `verify=carlos` — confirm a new OTP is generated for the victim by checking that subsequent brute-force attempts succeed.
4. Generate a numeric wordlist:
```bash
seq -w 0 9999 > codes.txt
```
5. Copy the raw POST request to `/login2`, replace the `mfa-code` value with `FUZZ`, and set `verify=carlos` in the cookie.
6. Run the brute-force attack:
```bash
ffuf -request request.txt -request-proto https -w codes.txt -mc all -fs <baseline_size>
```
7. Use the discovered OTP to send a valid POST to `/login2` with `username=carlos` and the found `mfa-code`.
8. Take the returned session cookie and send a GET request to `/my-account?id=carlos` — account access confirmed.

## Proof of Concept
```http
POST /login2 HTTP/2
Host: TARGET.web-security-academy.net
Cookie: verify=carlos; session=<attacker_session>
Content-Type: application/x-www-form-urlencoded

mfa-code=<brute-forced OTP>
```

## Impact
An unauthenticated attacker with only the victim's username can gain full access to their account — no password, no phishing, no victim interaction required.
This can lead to:
- Full account takeover of any user on the platform
- Access to all personal data, messages, and functionality tied to the account
- Unauthorized actions performed on behalf of the victim
- Potential privilege escalation if any account holds an elevated role

## Remediation
- Bind the OTP to the server-side session, not to a client-controlled cookie — the server must track who requested the OTP, not trust the client to report it
- Enforce strict rate limiting and account lockout on the `/login2` endpoint — a 4-digit OTP is only secure if guessing it is computationally impractical
- Set a short expiry on OTP codes (30–60 seconds) and invalidate them after a single use or a small number of failed attempts
- If IP-based brute-force protection is added, also enforce per-account lockout to prevent bypass via IP rotation

## References
- OWASP: Broken Authentication
- CWE-287: Improper Authentication
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- PortSwigger: 2FA broken logic