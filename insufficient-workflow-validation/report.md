# Vulnerability Report: Unauthorized Purchase via Insufficient Workflow Validation

**Severity:** Medium  
**CVSS Score:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N)  
**Date:** 2026-08-02  
**Target:** variableSub.web-security-academy.net  

## Executive Summary
A business logic vulnerability was identified in the purchasing workflow of the target application.
The application implements a multi-step checkout process — an order placement step followed by an order confirmation step.
The server assumes that any request reaching the confirmation endpoint (`/cart/order-confirmation?order-confirmed=true`) was legitimately preceded by a valid payment.
This assumption is never enforced — any authenticated user can send the confirmation request directly, bypassing the payment step entirely.
An attacker with any valid session and any cart contents can complete a purchase without spending any credits.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | Business Logic — Insufficient Workflow Validation |
| Endpoint | `GET /cart/order-confirmation?order-confirmed=true` |
| Method | GET |
| Protection | None — the confirmation endpoint performs no payment verification |
| Bypass | Sending the confirmation request directly after adding items to cart |
| Requirement | Any authenticated session with items in cart |
| User Interaction | Not required |

## Steps to Reproduce
1. Log in with valid credentials (`wiener:peter`) — a session cookie is issued.
2. Add the target item ("Lightweight l33t Leather Jacket", $1337) to cart.
3. Do not proceed to checkout. Instead, send the confirmation request directly:
   - `GET /cart/order-confirmation?order-confirmed=true`
4. Observe a `200 OK` response — the order is confirmed.
5. Check the account order history — the jacket has been purchased with no credits deducted.

## Proof of Concept
```http
GET /cart/order-confirmation?order-confirmed=true HTTP/2
Host: variableSub.web-security-academy.net
Cookie: session=<wiener_session>
```

**Response:**
```http
HTTP/2 200 OK
```

Order confirmed. Item purchased. Zero credits spent.

## Impact
Any authenticated user can purchase any item regardless of price by skipping the payment step entirely.
No special tooling is needed — a single GET request is sufficient.

This can lead to:
- Complete bypass of payment enforcement for any item in the store
- Direct financial loss for the platform on every exploited transaction
- No visible anomaly in normal application flows — the order appears legitimate

## Remediation
- The server must never rely on the client reaching the confirmation endpoint as proof that payment occurred. Payment state must be tracked server-side.
- Consider issuing a signed, single-use token during the checkout step, tied to the session and cart contents. The confirmation endpoint should reject any request that does not present a valid token.
- Conduct a full audit of other multi-step flows in the application for similar missing validation checks.

## References
- OWASP: Business Logic Vulnerabilities
- CWE-840: Business Rule Bypass
- PortSwigger: Insufficient Workflow Validation