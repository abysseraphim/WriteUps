# Vulnerability Report: SQL Injection with WAF Bypass via XML Encoding

**Severity:** High  
**CVSS Score:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
**Date:** 2026-07-21  
**Target:** web-security-academy.net  

## Executive Summary
A UNION-based SQL Injection vulnerability was identified in the `storeId` parameter of the stock check endpoint. A WAF was in place to block common SQL keywords, however it was bypassed by encoding the payload using XML numeric character entities — which the XML parser silently decodes before passing input to the application. This allowed full extraction of credentials from the database.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | UNION-based SQL Injection with WAF Bypass |
| Parameter | storeId (XML body) |
| Method | POST |
| Content-Type | application/xml |
| Database | PostgreSQL |

## Attack Scenario
An unauthenticated attacker sends a POST request to the stock check endpoint with a manipulated `storeId` value containing a UNION SELECT payload. The WAF inspects the raw request and sees only encoded characters — nothing suspicious. The XML parser then decodes the entities and passes the plain SQL to the application, which forwards it to the database unmodified. This allows the attacker to inject arbitrary SQL and extract any data from the database.

## Steps to Reproduce
1. Intercept a "Check Stock" POST request using Burp Suite
2. Locate the `storeId` field inside the XML body
3. Inject `1 ORDER BY 1` and `1 ORDER BY 2` to confirm 1 column in the original query
4. Attempt `1 UNION SELECT NULL` — observe WAF blocks it with 403
5. Encode the payload using XML numeric character entities and resend — observe bypass succeeds
6. Use `UNION SELECT version()` to confirm PostgreSQL
7. Extract table names via `information_schema.tables` with `string_agg`
8. Extract column names via `information_schema.columns`
9. Extract credentials with `string_agg(username || ':' || password, ',')`

## Proof of Concept
```http
POST /product/stock HTTP/2
Host: variableSub.web-security-academy.net
Cookie: <your cookies>
...
<?xml version="1.0" encoding="UTF-8">
    <stockCheck>
        <productId>
            1
        </productId>
        <storeId>
            1 <xml encoded: UNION SELECT version()>
        </storeId>
    </stockCheck>

```

## Impact
An unauthenticated attacker can extract all data from the database including credentials, enabling full account takeover. The presence of a WAF provides a false sense of security — the bypass requires no special tools, only basic XML encoding.

## Remediation
- Use parameterized queries / prepared statements to ensure user input is never interpreted as SQL
- Validate and sanitize input server-side, not only at the WAF layer
- Apply least privilege on the database user — the application account should not have read access to `information_schema`

## References
- https://owasp.org/www-community/attacks/SQL_Injection
- https://cwe.mitre.org/data/definitions/89.html
- https://portswigger.net/web-security/sql-injection