# Vulnerability Report: Reflected XSS via AngularJS Sandbox Escape and CSP Bypass

**Severity:** Medium  
**CVSS Score:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)  
**Date:** 2026-07-25  
**Target:** TARGET.web-security-academy.net  

## Executive Summary
A Reflected Cross-Site Scripting vulnerability was identified in the search functionality of the application.
The application is protected by a Content Security Policy that blocks inline scripts and restricts script sources to the same origin.
However, the application also loads AngularJS from that same origin — and AngularJS's template engine acts as a CSP-compliant JavaScript execution path.
By injecting an AngularJS directive into the search parameter, an attacker can abuse the `orderBy` filter combined with `$event.composedPath()` to escape the AngularJS sandbox and execute arbitrary JavaScript in the victim's browser.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | Reflected Cross-Site Scripting |
| Parameter | `search` (Query String) |
| Method | GET |
| Injection Context | HTML, inside an `ng-app` scope |
| Protection | CSP (`script-src 'self'`) + AngularJS sandbox |
| Bypass | AngularJS `orderBy` filter + `$event.composedPath()` + function aliasing |

## Steps to Reproduce
1. Open the target application and locate the search box — submit any input and confirm reflection in the HTML response.
2. Confirm HTML injection is possible by injecting an `<img>` tag and observing it rendered in the page.
3. Observe that the page loads AngularJS and the `<body>` tag carries the `ng-app` attribute — confirming Angular template expressions are evaluated.
4. Confirm CSTI by searching for `{{7*7}}` and observing `49` rendered on the page.
5. Observe that direct `alert()` calls inside Angular directives are blocked by the sandbox.
6. Confirm that `$event.composedPath()|orderBy:'x'` evaluates without error, establishing the `orderBy` gadget as a viable execution path.
7. Deliver the following payload via the `search` parameter:

```
<input id=l ng-focus="$event.composedPath()|orderBy:'(f=alert)(document.cookie)'">#l
```

8. The URL fragment `#l` auto-focuses the injected input, firing `ng-focus` without any user interaction beyond opening the link.
9. `document.cookie` is passed to `alert` via the aliased function — sandbox bypassed, XSS confirmed.

## Proof of Concept
```http
GET /?search=%3Cinput+id%3Dl+ng-focus%3D%22%24event.composedPath()%7CorderBy%3A%27(f%3Dalert)(document.cookie)%27%22%3E%23l HTTP/2
Host: TARGET.web-security-academy.net
```

**Payload (decoded):**
```text
<input id=l ng-focus="$event.composedPath()|orderBy:'(f=alert)(document.cookie)'">#l
```

## Impact
An attacker can craft a malicious URL containing the payload and trick a victim into opening it.
Since the XSS is reflected, the payload lives in the URL — making the attack surface anyone who opens the link. This can lead to:
- Executing arbitrary JavaScript in the victim's browser under the target origin
- Session hijacking via cookie theft
- Performing unauthorized actions on behalf of the victim
- Redirecting the victim to phishing pages or injecting fake UI elements into the DOM

## Remediation
- Never reflect user-controlled input into an HTML context without proper output encoding
- Avoid serving outdated versions of AngularJS — versions below 1.6 include a sandbox that was repeatedly bypassed and is not a reliable security control
- Do not rely on `script-src 'self'` alone as a CSP policy — any trusted same-origin script that evaluates expressions (such as AngularJS) becomes an execution gadget
- Replace blanket `'self'` script allowances with nonce- or hash-based CSP to restrict which specific scripts may run
- Apply a strict Content Security Policy as a defense-in-depth layer, not as the primary XSS defense

## References
- OWASP: Cross-Site Scripting (XSS)
- CWE-79: Improper Neutralization of Input During Web Page Generation
- PortSwigger: Reflected XSS with AngularJS sandbox escape and CSP
