# Lab: Password reset poisoning via middleware

| Field | Details |
|-------|---------|
| **Provider** | PortSwigger |
| **Difficulty** | Practitioner |
| **Category** | Broken Authentication |
| **Date** | 2026-07-26 |

---

## Summary

Password reset poisoning via middleware is a lab in the PortSwigger Web Security Academy. In this lab we have a user's credentials and we can log in to wiener's account. However, there is a forgot password feature too, which allows users to restore their forgotten passwords.

In this writeup, I'll walk through the entire manual exploitation flow step by step.

The task is to take over somebody else's account. The victim's username is `carlos`.

![image](images/1-labinfo.png)

---

## Reconnaissance

First, opening the target — it's just a normal looking weblog where users can add posts and...
nothing suspicious at first sight.

![img](images/2-normalLookingBlog.png)

![img](images/3-nothingSpecial.png)

<br>

When I tried to log in to my account, the forgot password link was eye-catching.
You know, forgot password implementation is so important in authentication flows.

![img](images/4-login.png)

So I clicked that and next I had to enter a username or email:

![img](images/5-forgotPasswordClicked.png)

![img](images/6-enteredMyUsername.png)

When I submitted the username (wiener), a POST request was sent to the website and the response was telling me to check my email for a reset password link.

![img](images/7-mailSent.png)

So I opened the exploit server → email client and saw the reset password link in there...

![img](images/8-normalLinks.png)

But how does the application know what URL to send to the client?
There are two possibilities:
1. It's hardcoded
2. It's built dynamically from somewhere

The first possibility is safer against this issue by default but is less desirable due to scalability concerns.
The second may be vulnerable in multiple ways — for example, `attacker.com` might be blocked, but `site.com@attacker.com` may be allowed.

Anyway, there has to be a parameter passing the address to the backend, so the backend knows what to write in the email (or the backend may construct it itself using request metadata).

This input can come from a query string, POST body parameters, or headers.
If there are parameters, we can try to change them during recon and bypass protections if possible.
But if no parameters are visible, headers become the most important thing to look at — especially: `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `Forwarded`.

First, you need to know a website may or may not be behind a CDN.
Usually, if there is no CDN in the way, we can try `Host header poisoning` by changing the `Host` header directly.

But if there is a CDN (CDNs work based on SNI and the Host header — SNI handles TLS and the Host header handles HTTP routing. When a request arrives at the middle server, it needs to know where to forward it), we can try changing or adding forwarding headers like `X-Forwarded-For`, `X-Forwarded-Host`, or `X-Host`.

And as you just saw in the reset password link, this part: `/forgot-password?temp-forgot-password-token=<token>` was concatenated to the URL.

So what happens if an attacker is able to make the application append this part to their own server URL?
They can simply check the access logs and steal the victim's token.

In a real-world scenario, you'd have a web server with a domain (or just a public IP) and try to poison the application with it. But here, as a lab, there's an exploit server that makes this easy — and it even has a button to inspect the access log:

![img](images/9-accessLog.png)

Access logs:

![img](images/10-weCanSeeTheLog.png)

<br>

My next move was changing the headers (even Referer) and adding some proxy headers.
Because when the target is using a reverse proxy or CDN (and most sites do nowadays), if the Host header changes, the request may not reach the server at all.

![img](images/11-PoisonedHeaders.png)

I went back to check emails again and it worked!
The new URL was pointing to the attacker's server.

![img](images/12-workedButWhichOne.png)

I clicked on that link and then checked the logs:

![img](images/13-accessTokenLogged.png)

My request was logged and I was able to see the full token.
But how could I know which header did it? It actually doesn't matter at this point since it's working the way I want — but just to make it clear... (read the exploitation part).

---

## Exploitation

After that great recon, I just needed to change a few parts of my POST request to `/forgot-password`.
So I changed the username to the victim's username (carlos).
And to figure out which header actually did the job, I added a special path to each one (their shortened names as identifiers).

![img](images/14-carlosAndIdentifiersForHeaders.png)

Then I checked the access log again, waiting for the victim to click on the link, and this appeared:

![img](images/15-gotTheToken.png)

It turned out that `X-Forwarded-Host` was doing the job.

So I just needed to copy the whole thing (`/forgot-password?temp-forgot-password-token=<actual token>`) and add it to the URL.

![img](images/16-enteredToken.png)

<br>

A new page opened and I was able to change `carlos`'s password.
I changed it to `hacked`.

![img](images/17-passReset.png)

<br>

Then I just needed to log in using the victim's credentials...

![img](images/18-login.png)

---

## Final Payload:

There was no payload at all — this vulnerability type just needs deep understanding and analysis to discover.

---

## Result

One-click, full account takeover —
a link is sent to the victim, and the sender is not the attacker, it's the legitimate application.
If the user clicks on that link, they become the victim of an account takeover.

The scary part? From the victim's perspective, everything looks completely normal.
They clicked a password reset link that came from the real application, from the real domain, in a legitimate-looking email.
There's no red flag, no suspicious sender, nothing to hint that something is wrong.
That's what makes this one nastier than most — the application itself is used as the delivery mechanism.

![img](images/19-solved.png)

---

## Impact & Remediation

The application trusts the `X-Forwarded-Host` header and uses it to construct the password reset URL without any validation.
This means an attacker can redirect the reset link to any server they control — and since the email comes from the legitimate application, the victim has no reason to be suspicious.

The impact is a one-click account takeover. The attacker doesn't need the victim's password, doesn't need to be on the same network, and doesn't need to intercept any traffic. They just need the victim to click a link — which is exactly what a password reset email is designed to make people do.

For remediation:

The application should never use client-supplied headers to construct URLs in sensitive flows like password resets. The reset URL should be built from a hardcoded base URL configured on the server side.

If the application sits behind a reverse proxy or CDN and needs to trust forwarding headers, that trust should be scoped strictly — only accept `X-Forwarded-Host` from known, trusted proxy IPs, and reject it from everyone else.

Password reset tokens should be single-use and short-lived. If a token gets stolen and used, the window of exploitation should be as small as possible.

---

## Takeaway

This one is a good example of how trust in the wrong place can turn a security feature into an attack vector.
The password reset flow was working as intended — the problem was what it was using to build the reset URL.

A few things worth remembering:

* **Headers are user-controlled input.** `X-Forwarded-Host`, `X-Forwarded-For`, `Forwarded` — these are all just HTTP headers. Anyone can set them. If the application uses them without validation, they're an injection point, just like any other parameter.

* **Sensitive flows deserve extra scrutiny.** Password reset, email change, account recovery — these are high-value targets because a successful attack directly leads to account takeover. Any dynamic behavior in these flows (especially URL construction) is worth testing carefully.

* **The legitimate application becoming the attacker's delivery mechanism is the worst case.** Phishing links from unknown senders get flagged and ignored. A password reset email from the real application, with the real domain in the From field, is something users are trained to click. That's a social engineering advantage the attacker gets for free.

* **When no visible parameters exist, look at headers.** If the reset URL changes based on something but there's no obvious parameter controlling it, the source is usually the `Host` header or a forwarding header. Always test both, especially when a CDN or reverse proxy is involved.