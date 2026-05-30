---
title: "One-Click Account Takeover via CSRF on Email Change Endpoint"
date: 2026-01-01
tags: ["csrf", "ato", "account-takeover", "web"]
summary: "A critical CSRF vulnerability in a popular reading platform's email change endpoint that required nothing more than a single click to fully hijack an account."
---

## Background

I've been doing more web research lately, mostly just poking at apps I actually use day-to-day. The target here is a popular reading and annotation platform — one of those tools that lets you save highlights from books and articles and resurface them over time. Lots of people have years of personal reading data in there, which made the account security question interesting to me.

I had a hypothesis: what does the email change flow look like? Sensitive account actions like this are often where developers cut corners. They're not the login page — nobody's staring at them — so CSRF protections sometimes get skipped, and re-authentication prompts often never make it into the design.

Spoiler: that hypothesis was right.

---

## Finding the Vulnerability

I opened Burp Suite and started mapping out the account settings. When I changed my email address in the UI, I was watching the Proxy tab to catch the outgoing request.

What came out stopped me cold:

```
GET /api/change_email/?newEmail=mynewemail@example.com HTTP/1.1
Host: [target]
Cookie: sessionid=...
```

A **GET request**. For a state-changing operation. No POST body, no CSRF token, no `X-Requested-With` header, no current password confirmation. Just a plain GET with the new email as a query parameter.

I sat there for a second making sure I wasn't misreading the request. Nope. That's really it.

The implications were immediate: any authenticated user who clicks a link to this URL will silently change their account email to whatever the `newEmail` parameter says. And because this is a GET request, the browser sends the session cookie automatically — no cross-origin restrictions apply.

---

## The Attack Chain

The full exploit is painfully simple:

**Step 1 — Craft the link.**

```
https://[target]/api/change_email/?newEmail=attacker@evil.com
```

**Step 2 — Get the victim to click it.**

Send it via email, embed it in a webpage, paste it in a chat message, anything. The victim just needs to be logged in when they click.

**Step 3 — The server processes it immediately.**

The victim's account email is now `attacker@evil.com`. No confirmation dialog. No verification email sent to the old address. No current-password prompt. It just happens.

**Step 4 — Trigger a password reset.**

The attacker navigates to the platform's password reset page, enters `attacker@evil.com`, and receives the reset link in their own inbox. They set a new password.

**Step 5 — Full account takeover.**

The legitimate user is now locked out. The attacker has complete access to everything: their library, their highlights, their subscriptions, their connected integrations. All of it.

CVSS v3.1: **9.0 (Critical)** — `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H`

---

## Why This Worked

There are three things that all had to be wrong simultaneously for this to work, and they were all wrong at the same time.

**1. State change via GET request.** HTTP GET is supposed to be idempotent — calling it shouldn't change anything. Browsers and proxies treat GET requests as safe, which is why a `<img src="...">` or a simple hyperlink can trigger one silently. Putting a sensitive operation behind a GET endpoint fundamentally breaks the web's security model.

**2. No CSRF token.** Even if you've accidentally used GET, a CSRF token would stop this cold. The attacker's crafted link wouldn't know the victim's token, so the server would reject the request. No token means no protection.

**3. No re-authentication.** Changing your account email should require confirming who you are. Every major platform does this: type your current password before we'll update your primary contact method. Without it, session cookies alone are sufficient to execute the change — and those cookies are exactly what CSRF exploits.

None of these is a subtle bug. Any one of them being present would have killed the attack.

---

## Impact

- **Confidentiality:** An attacker gains access to everything in the victim's account — years of saved highlights, personal notes, reading history, and any connected integrations.
- **Integrity:** They can modify or delete data, change account settings, disconnect legitimate sessions.
- **Availability:** The legitimate user is permanently locked out. There's no path back to the account once the email and password are both changed.

The CVSS scope is "Changed" because the compromise extends beyond just this application — the attacker now controls an identity that may be used for SSO into other services.

---

## Remediation

The fixes here are straightforward:

**Enforce POST for state-changing operations.** Any endpoint that modifies data should require a POST request. This alone would prevent simple link-based CSRF.

**Require current password.** Before updating the email address, require the user to re-enter their current password. An attacker can't CSRF a field they don't know the value of.

**Implement CSRF tokens.** A server-side anti-CSRF token — validated on every state-changing request — is the standard defense here. Frameworks like Django have this built in; it just needs to not be bypassed.

**Send confirmation to both addresses.** Even as a secondary defense, notifying the old email when an address change is requested gives the legitimate owner a chance to notice and react.

---

## Disclosure

Reported to the vendor. The vulnerability was acknowledged and fixed. This post is published after the fix was deployed.
