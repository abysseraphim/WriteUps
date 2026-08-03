# Vulnerability Report: Unauthorized Purchase via Integer Overflow in Cart Price Calculation

**Severity:** Medium  
**CVSS Score:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N)  
**Date:** 2026-08-03  
**Target:** `<target>.web-security-academy.net`

---

## Executive Summary

An integer overflow vulnerability was identified in the server-side cart total calculation of the application.
The application accumulates item costs using a signed 32-bit integer. By sending a large number of add-to-cart requests with the maximum allowed quantity, an authenticated attacker can cause the total price to overflow past `INT32_MAX` (`2,147,483,647`), wrapping it to a large negative value.
From there, the attacker can carefully tune the cart — using additional items — to bring the total to a small positive number within their available credit balance, then complete a legitimate-looking checkout.
In this case, a $1,337.00 leather jacket was purchased for $32.30.

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| Type | Business Logic — Integer Overflow in Monetary Calculation |
| Endpoint | `POST /cart` |
| Method | POST |
| Parameter | `quantity` |
| Protection | None — no server-side cap on cumulative cart total or overflow detection |
| Bypass | Sending repeated add-to-cart requests with `quantity=99` to overflow the signed integer accumulator |
| Requirement | Any authenticated session on the platform |
| User Interaction | Not required |

---

## Steps to Reproduce

1. Log in with a valid account (e.g., `wiener:peter`) — the account starts with $100.00 in store credit.
2. Navigate to the target product page (leather jacket, priced at $1,337.00) and add it to the cart.
3. Intercept the `POST /cart` request in Burp Suite — it includes `productId`, `redir`, and `quantity` parameters.
4. Send the request to Burp Intruder. Set `quantity` as the payload position.
5. Configure the attack: payload type `Null payloads`, repeat 162 times, `quantity=99`, max concurrent requests = 1.
6. Run the attack. After 162 requests, the cart total wraps to approximately `-2,147,483,647`.
7. Continue sending batches of requests (~122 more) until the total reaches approximately `-6,406,096`.
8. Switch to Burp Repeater and manually add 47 more jackets to bring the total to `-122,196`.
9. Find a cheaper item in the shop (e.g., priced at $89.59). Calculate how many units are needed to fill the remaining gap: `122,196 / 8,959 ≈ 14`.
10. Add 14 units of the cheaper item to the cart.
11. Observe the cart total is now `$32.30` — within the $100.00 credit.
12. Click "Place Order" — the order is accepted and the lab is solved.

---

## Proof of Concept

**Add-to-cart request (repeated ~330 times with `quantity=99`):**
```http
POST /cart HTTP/2
Host: <target>.web-security-academy.net
Cookie: session=<YOUR_SESSION>
Content-Type: application/x-www-form-urlencoded

productId=1&redir=PRODUCT&quantity=99
```

**Cart total progression:**
```
After 162 requests  →  ~  -2,147,483,647   (INT32 overflow confirmed)
After 200 requests  →     -1,634,470,996
After 284 requests  →        -6,406,096
After +47 jackets   →          -122,196
After +14 cheap items →         +3,230   ($32.30)
```

**Final cart — order placed successfully at $32.30 for a $1,337.00 item.**

---

## Impact

An authenticated attacker can purchase any item in the store — regardless of its price — for a fraction of its actual cost, or effectively for free.
The attack requires no special privileges beyond a standard user account and no victim interaction.
The only constraint is the time and number of requests needed to reach the overflow threshold, which is fully automatable.

In a real application, this would result in:
- Direct and repeatable financial loss for the business
- Bypassing of all price-based access controls (e.g., premium products, limited editions)
- Potential for scaled abuse — any number of high-value items can be acquired this way
- The transaction appears completely legitimate on the server side, making detection difficult without anomaly monitoring on quantity patterns

---

## Remediation

- Use arbitrary-precision arithmetic or a `decimal` / `bigint` type for all monetary calculations — never native signed integers.
- Enforce a server-side cap on the maximum quantity per item per request and per session within a time window.
- Validate that the final cart total is always a positive value within a reasonable expected range before processing payment.
- Reject or flag any cart state where the total is negative or suspiciously low relative to the items present.
- Implement rate limiting on the add-to-cart endpoint to detect and block high-frequency automated requests.

---

## References

- CWE-190: Integer Overflow or Wraparound
- CWE-20: Improper Input Validation
- OWASP: Business Logic Vulnerabilities
- OWASP Top 10 A04:2021 — Insecure Design
- PortSwigger: Business Logic Flaws