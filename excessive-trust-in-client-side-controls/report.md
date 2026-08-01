# Vulnerability Report: Price Manipulation via Client-Side Trust in Purchase Workflow

**Severity:** Medium  
**CVSS Score:** 4.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N)  
**Date:** 2026-08-01  
**Target:** variableSub.web-security-academy.net  

## Executive Summary
A business logic vulnerability was identified in the product purchasing workflow of the application.
The server accepts the item price directly from the client-side POST request when adding a product to the cart,
with no server-side validation against the actual product price stored in the database.
Any authenticated user can modify the price parameter in the add-to-cart request to an arbitrary value
and complete a purchase at that manipulated price — resulting in direct financial loss for the business.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | Business Logic — Excessive Trust in Client-Side Controls |
| Endpoint | `POST /cart` |
| Method | POST |
| Protection | None — price parameter is accepted from client without validation |
| Bypass | Modifying the `price` parameter in the POST body before it reaches the server |
| Requirement | Any authenticated session on the platform |
| User Interaction | Not required |

## Steps to Reproduce
1. Log in with valid credentials (`wiener:peter`) — a session cookie is issued.
2. Navigate to any product page and intercept the add-to-cart request.
3. Observe that the POST body contains a `price` parameter alongside `productId` and `quantity`.
4. Modify the `price` parameter to an arbitrary low value (e.g., `1300` for $13.00).
5. Forward the request — the item is added to the cart at the manipulated price.
6. Place the order — the server accepts it and completes the purchase at the tampered price.

## Proof of Concept
```http
POST /cart HTTP/1.1
Host: variableSub.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Cookie: session=<wiener_session>

productId=1&redir=PRODUCT&quantity=1&price=1300
```

**Result:** Item originally priced at $1337.00 was purchased for $13.00.

## Impact
Any authenticated user can purchase any item on the platform for an arbitrary price of their choosing,
including values close to zero.
The server processes the order without any validation against the actual product price,
meaning the financial loss scales directly with how many users discover and abuse this vulnerability.

This can lead to:
- Direct and repeatable financial loss for the business on every manipulated transaction
- Acquisition of high-value items at near-zero cost by any authenticated user
- Order records in the database containing incorrect pricing data, corrupting sales and inventory reporting
- Large-scale abuse if the vulnerability is discovered publicly, with no server-side mechanism to detect or rate-limit it

## Remediation
- The price must never be sourced from the client. The server should calculate the total based on the `productId` and `quantity` using its own database — the client should only send what the user selected, nothing else.
- Any pricing logic that exists in the frontend (hidden fields, JavaScript, POST parameters) provides zero security. It is UI only and must not be treated as a trust boundary.
- Validate all order totals server-side before processing payment or confirming a purchase, and reject any request where the submitted price does not match the server's calculated value.
- Conduct a full audit of other transactional endpoints for similar client-supplied values being accepted without validation.

## References
- OWASP: Security Misconfiguration / Business Logic Flaws
- CWE-602: Client-Side Enforcement of Server-Side Security
- CWE-807: Reliance on Untrusted Inputs in a Security Decision
- PortSwigger: Business Logic Vulnerabilities