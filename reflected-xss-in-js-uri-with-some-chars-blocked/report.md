# Vulnerability Report: Reflected XSS via JavaScript URL with Character Restrictions

**Severity:** High  
**CVSS Score:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)  
**Date:** 2026-07-23  
**Target:** TARGET.web-security-academy.net  

## Executive Summary
A Reflected Cross-Site Scripting vulnerability was identified in the blog post navigation functionality of the application.
The application places user-controlled input inside a `javascript:` URL scheme, which is inherently dangerous.
While the application imposes character-level restrictions — blocking parentheses and spaces — these filters are insufficient.
By combining arrow functions, comma expressions, `throw` statements, and browser API abuse (`window.onerror`, `window.toString`),
an attacker can execute arbitrary JavaScript in the victim's browser without using any of the blocked characters.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | Reflected Cross-Site Scripting (XSS) |
| Parameter | `postId` (Query String) |
| Method | GET |
| Injection Context | JavaScript string inside a `javascript:` URL |
| Filter | Character blocklist (parentheses and spaces blocked) |
| Bypass | Arrow functions + comma expressions + `window.onerror` + `window.toString` abuse |

## Steps to Reproduce
1. Open the target application and navigate to any blog post.
2. Observe the "Back to blog" link — its `href` is a `javascript:` URL containing a `fetch()` call that reflects part of the current URL (path + query string) inside a JavaScript string.
3. Inject a single quote (`'`) into the `postId` parameter and confirm a client-side JavaScript syntax error — this proves the input is reflected inside a JS string context.
4. Confirm that adding an `&` after `postId=3` suppresses the error, indicating we can extend the argument list.
5. Confirm that modifying the path also affects the reflected JS code.
6. Observe that parentheses `()` and spaces are blocked by the filter.
7. Deliver the following payload via the `postId` parameter in the URL:

```
/post?postId=3&'},x=param=>{throw/**/onerror=alert,1337},toString=x,window+'',{foo:'
```

8. Click the "Back to blog" link to trigger the `javascript:` URL — the `fetch()` call evaluates all arguments, executing the injected payload.
9. `alert(1337)` fires.

## Proof of Concept
```http
GET /post?postId=3&%27},x=param=>%7Bthrow/**/onerror=alert,1337%7D,toString=x,window%2B%27%27,%7Bfoo:%27 HTTP/2
Host: variableSub.web-security-academy.net
```

**Payload (decoded):**
```text
postId=3&'},x=param=>{throw/**/onerror=alert,1337},toString=x,window+'',{foo:'
```

## Impact
An attacker can craft a malicious URL containing the payload and trick a victim into visiting it and clicking the link.
Since the XSS is reflected, the payload lives in the URL — making the attack surface anyone who opens the link. This can lead to:
- Executing arbitrary JavaScript in the victim's browser under the target origin
- Session hijacking if authentication cookies are accessible
- Performing unauthorized actions on behalf of the victim
- Stealing sensitive data rendered in the page
- Redirecting the victim to phishing pages or injecting fake UI elements into the DOM

## Remediation
- Never place user-controlled input inside a `javascript:` URL — this pattern is inherently unsafe regardless of any filtering applied to the input
- Avoid constructing JavaScript URLs dynamically; use standard event listeners (`addEventListener`) instead of `javascript:` hrefs
- Do not rely on character blocklists for XSS prevention — they are always bypassable
- Use proper output encoding for the target context; input reflected inside JavaScript strings must be JavaScript-escaped, not just HTML-encoded
- Apply a strict Content Security Policy (CSP) as a defense-in-depth layer

## References
- OWASP: Cross-Site Scripting (XSS)
- CWE-79: Improper Neutralization of Input During Web Page Generation
- PortSwigger Web Security Academy: Reflected XSS in a JavaScript URL with some characters blocked