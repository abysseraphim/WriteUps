# Vulnerability Report: Blind SQL Injection

**Severity:** High  
**CVSS Score:** 7.5 (string: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
**Date:** 2026-07-20  
**Target:** web-security-academy.net  

## Executive Summary
A Blind SQL Injection vulnerability was identified in the tracking cookie parameter, 
allowing extraction of sensitive data from the database without error-based feedback.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | Blind Boolean-based SQL Injection |
| Parameter | TrackingId (Cookie) |
| Method | GET |
| Database | PostgreSQL |

## Attack Scenario  
An unauthenticated attacker intercepts the TrackingId cookie and injects boolean-based payloads to enumerate the database schema and extract data character by character.  
This results in full credential disclosure and account takeover of any user, including administrators.

## Steps to Reproduce
1. Intercept a GET request to the home page using Burp Suite
2. Locate the TrackingId cookie in the request headers
3. Append the following payload to the cookie value:
   ' AND '1'='1
4. Observe that the "Welcome back" message appears (condition: true)
5. Change the payload to `' AND '1'='2` and confirm the message disappears (condition: false)
6. Use SUBSTRING() with boolean conditions to enumerate database tables, columns, and data

## Proof of Concept
```http
GET / HTTP/2
Host: variableSub.web-security-academy.net
Cookie: TrackingId=<variableCookie>' AND SUBSTRING((SELECT version()),1,1)='P'-- -; session: <yourSessionGoesHere>

<rest of the request>
```

## Impact
An attacker can extract all data from the database including credentials,
enabling full account takeover.  

## Remediation
- Use parameterized queries / prepared statements
- Implement input validation
- Apply least privilege on DB user

## References
- https://owasp.org/www-community/attacks/SQL_Injection
- https://cwe.mitre.org/data/definitions/89.html
- https://portswigger.net/web-security/sql-injection/blind