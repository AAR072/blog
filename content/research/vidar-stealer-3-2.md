---
title: "Reverse engineering Vidar Stealer 3.2"
date: 2026-08-30
tags: ["malware", "reverse-engineering", "vidar", "infostealer", "threat-intel"]
summary: "A walk through Vidar Stealer 3.2: its encrypted configuration, Telegram and Epic Games dead drops, multipart C2 protocol, server-issued token, collection flow, and Base64 archive exfiltration."
---

I recently analyzed a loader submitted to [CAPE](https://www.capesandbox.com/analysis/83269/) and two unpacked payloads it produced. The loader is a signed-looking Go binary. Underneath it is a native 64-bit build of Vidar Stealer 3.2 with no normal import table, an encrypted configuration, three ways to find its C2, and a multipart protocol for checking in and uploading stolen data.

The short version is:

```text
Go loader
  → unpacks Vidar 3.2
  → resolves Windows APIs by hash
  → decrypts its embedded C2 table
  → tries a direct receiver, then Telegram and Epic Games dead drops
  → sends HWID + build ID to the receiver
  → receives collection flags and a token
  → collects data into an archive
  → Base64-encodes and uploads it
```

The server answered my sandbox with `block`, so this run stopped before collection. Static analysis still exposes the rest of the protocol, including the accepted JSON response and final upload format.

I also wrote [vidar32-toolkit](https://github.com/AAR072/vidar32-toolkit), an extraction and reversing toolkit for Vidar 3.2 samples. It can locate and decrypt the fixed-field configuration, fingerprint it, scan related artifacts, summarize PCAPs, and decode collected `ENC:` dead-drop records without executing the malware.

## The samples

The original file submitted to CAPE is a 4.4 MB PE32+ Go executable:

```text
SHA-256  336b3fc46fb10b237b02898203558f045633bdb4585f229551ac1d417f2c93f1
Size     4,448,168 bytes
Compiler Go 1.23.1
Signer   Onyx Beacon Studios (invalid, self-signed certificate)
```

It acts as the loader. I did most of the reverse engineering on two unpacked copies of the native payload:

```text
a23acd6904fea21a155034508270de7af18cf6cf8a5697cf2692cdd9b2815c97
73f7f84d9624bdf4b8ace3ca42a6259d2c81ea42927fa3bdb4b0c724dbe72076
```

They have identical PE headers and executable code. The difference is runtime state: the first has host identifiers and a plaintext configuration cache populated, while most of the same region is still zero in the second. Having both was useful because one showed the clean pre-initialization layout and the other showed what Vidar writes there after decrypting its configuration.

The payload has no entries in its PE import directory. Instead, it walks the PEB, finds loaded DLLs, and resolves API names using a custom hash with initial value `451044547` and multiplier `16778787`.

The APIs it resolves give away most of the capability set:

```text
WinHTTP                       networking and TLS
registry enumeration         application data discovery
process/thread enumeration   process inspection
ReadProcessMemory            reading data from other processes
BCrypt and CryptoAPI         hashing and decryption
file enumeration/copying     collection and archive construction
VirtualAllocEx, WriteProcessMemory,
NtQueueApcThread*, NtCreateThreadEx  process/thread manipulation
```

## Finding the configuration

The encrypted configuration starts at file offset `0x1540D0`. The first 16 bytes are the repeating XOR key:

```text
4dafee62c692656b15dec057e338115c
```

The layout is fixed:

```text
+0x000  key[16]
+0x010  version ciphertext; length at +0x030
+0x031  build ID ciphertext; length at +0x071
+0x072  first C2 record
```

Each C2 record is `0x243` bytes:

```text
+0x000  URL ciphertext;        length at +0x100
+0x101  tag ciphertext;        length at +0x141
+0x142  user-agent ciphertext; length at +0x242
```

Vidar runs the fields through the same repeating XOR key and copies each decrypted record into a runtime table. The plaintext records have a `0x240` stride: 256 bytes for the URL, 64 for the tag, and 256 for the user agent.

Decrypting the header gives:

```text
Version   3.2
Build ID  e53c0776fdba467447b61be1a2bc4027
```

The build ID is important. It is not a panel password, but it acts as a campaign/customer identifier and routing key every infected host sends to the C2.

You can reproduce this part with my [Vidar 3.2 config extractor](https://github.com/AAR072/vidar32-toolkit):

```sh
git clone https://github.com/AAR072/vidar32-toolkit.git
cd vidar32-toolkit
./vidar32_toolkit.py config ./extracted-payload
# Or emit machine-readable output:
./vidar32_toolkit.py --json config ./extracted-payload
```

Use an unpacked sample from an isolated analysis environment. Basic configuration extraction is offline; fetching public dead drops is an explicit `--fetch` mode. There is no reason to execute a stealer just to read its configuration.

## Three paths to the C2

This build contains three records. The first is a direct receiver:

```text
URL  https://185.229.225.31
Tag  <empty>
UA   Mozilla/5.0 (iPhone; CPU iPhone OS 26_3_1 like Mac OS X) ...
```

The next two are dead drops rather than receivers:

```text
Telegram  https://telegram.me/nag0a
Epic      https://dev.epicgames.com/community/api/user_profiles/profile.json?hash_id=EMqJL
Tag       o0oi1
UA        Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:34.0) ...
```

A dead drop is a public page the malware uses as a tiny configuration file. The operator can change the real receiver without rebuilding the malware: edit the Telegram page or Epic profile and every infected machine discovers the new address on its next check-in.

The C2 selection routine walks the records in order. An untagged URL is used directly. For a tagged record, Vidar:

1. downloads the public page with the record's user agent;
2. searches the response for the tag, `o0oi1` here;
3. skips an optional delimiter such as `|`, a colon, or whitespace;
4. copies the following value until whitespace, markup, or another `|`;
5. decrypts the value if it starts with `ENC:`; and
6. adds `https://` if the result has no scheme.

The Telegram page held:

```text
o0oi1 ENC:5991e1ebab5d26c9b739b5af8db1
```

The Epic profile's `interests` field held:

```text
o0oi1 enc:5991e1ebe9027990e83cedac89f8263dbc
```

## Decrypting the dead drops

The `ENC:` layer is separate from the embedded configuration encryption. Vidar hex-decodes the value, hashes the hardcoded string `Glasikprostik` with SHA-256, then XORs the ciphertext with the 32-byte digest.

```text
SHA256("Glasikprostik")
= 2de380c59a6f48a8d0589bc0ffd64a5cc8faa01c87a69e5a9f1ec9777eb74cbe
```

An offline decoder is only a few lines:

```python
import hashlib

def decode_vidar_enc(value: str) -> str:
    value = value.removeprefix("ENC:").removeprefix("enc:")
    ciphertext = bytes.fromhex(value)
    key = hashlib.sha256(b"Glasikprostik").digest()
    return bytes(
        byte ^ key[index & 31]
        for index, byte in enumerate(ciphertext)
    ).decode()
```

The two values decrypt to:

```text
Telegram  tra.12naga.org      → https://tra.12naga.org/
Epic      tra.sm188dvlv.lat   → https://tra.sm188dvlv.lat/
```

The same `nag0a` identity appears on both services. The Epic account was also named `nag0a`, had numeric ID `2036619`, and used hash ID `EMqJL`. Combined with the shared marker and timing, these are clearly two dead drops for the same deployment.

`Glasikprostik` is useful for identifying related builds, but I would not treat it as an operator fingerprint. It appears to be a family or builder constant.

## The first check-in

Once Vidar has a receiver, it sends an unusual HTTPS `GET /` with a multipart body. There is no HTTP Authorization header. Identity and routing live inside three form fields:

```text
Content-Disposition: form-data; name="hwid"

FE72EBABA2082352DDB4-65b178c1-239c-B21E683
```

```text
Content-Disposition: form-data; name="build_id"

e53c0776fdba467447b61be1a2bc4027
```

```text
Content-Disposition: form-data; name="format"

json
```

The complete captured body was 345 bytes. The HWID changes between machines, confirming that it is generated from host, volume, and GUID material rather than embedded in the sample. The build ID stays fixed and tells the service which campaign configuration to return.

The direct receiver behaved differently depending on the request. Public scanners saw an ordinary browser GET return HTTP 404. A correctly formed Vidar check-in received:

```text
HTTP/1.1 200 OK
Content-Type: text/plain

block
```

That five-byte response matters. It shows the root route recognizes bot-shaped requests, but `block` is not the JSON object the client expects. The parser rejects it, no token is issued, and the malware retries or advances to another configured record.

I cannot prove why the server rejected this host. It could be an expired build, a blocked sandbox/ASN, campaign allowlisting, deny mode, or partially disrupted infrastructure. The answer lives server-side, so anything more specific would be guessing.

## What the C2 sends back

An accepted response is JSON. The parser requires a `token` and recognizes at least these configuration keys:

```text
token
cryptocurrency
steal_discord
telegram
steam
azure
screenshot
antivm
debug
loader
thread_count
zip_threshold
```

These fields decide which collectors run, whether anti-VM checks and screenshots are enabled, how many collection threads to use, when to split archives, and whether to execute a secondary payload.

The `token` is generated or supplied by the receiver and stored in the client context. It is later sent back with the stolen archive. It is not embedded in the binary, is not a Telegram Bot API token, and is not an operator-panel credential.

This distinction is easy to miss during triage. The sample contains several credential-looking strings, but none grants access to a panel:

```text
build ID                 campaign routing identifier
HWID                     victim identifier
response token           server-issued bot/session token
o0oi1                    dead-drop marker
EMqJL / 2036619          public Epic profile identifiers
config XOR key           local decryption material
SHA-256(Glasikprostik)   local dead-drop decryption material
```

## Collection and upload

If the JSON is accepted, the flags drive the collection stage. The binary contains paths for browser and application data, credentials, cryptocurrency wallets, Discord, Telegram, Steam, Azure, screenshots, process inspection, and optional secondary-payload loading.

Collected files are assembled into an in-memory archive. Before upload, Vidar Base64-encodes the raw archive and constructs another multipart request with four fields:

```text
token
build_id
mode
file_data
```

`file_data` is the Base64 archive. The response token ties the upload to the bot session, while the build ID routes it back to the right campaign. The request goes through the malware's WinHTTP wrapper.

The secure-request path sets flags that allow invalid, self-signed, or mismatched certificates. That explains how the sample talks HTTPS to a literal IP using its self-signed certificate without failing validation.

So the complete protocol is:

```text
decrypt embedded records
        │
        ├─ direct HTTPS receiver
        ├─ Telegram page ── decrypt ENC value ── receiver
        └─ Epic profile  ── decrypt ENC value ── receiver
                                    │
                                    ▼
                 multipart GET: hwid + build_id + format=json
                                    │
                       accepted JSON + server token
                                    │
                 collectors selected by response feature flags
                                    │
                                    ▼
             multipart upload: token + build_id + mode + file_data
```

My sandbox never passed the `block` response, so there was no stolen archive in the reviewed traffic. The upload path above comes from the binary, not from pretending the failed run exfiltrated anything.

## Infrastructure

The strongest reportable endpoint is:

```text
185.229.225.31:443/tcp  confirmed Vidar bot check-in/exfiltration receiver
```

The two fallback hostnames were behind Cloudflare when checked:

```text
tra.12naga.org
tra.sm188dvlv.lat
```

Do not block or report the shared Cloudflare edge IP as the malware origin. Use the malicious hostnames. I also found no evidence of a separate operator panel. Vidar can separate its bot receivers from the central MaaS panel, and guessing panel paths or calling SSH a panel would weaken the finding.

Runtime artifacts from this sample include:

```text
Registry  HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TS_b2f578ca
Path      C:\ProgramData\2365e17917c
Mutex     AFDSE3esh32le
```

## IOCs

```text
# Samples
336b3fc46fb10b237b02898203558f045633bdb4585f229551ac1d417f2c93f1
a23acd6904fea21a155034508270de7af18cf6cf8a5697cf2692cdd9b2815c97
73f7f84d9624bdf4b8ace3ca42a6259d2c81ea42927fa3bdb4b0c724dbe72076

# Network
185.229.225.31:443
tra.12naga.org
tra.sm188dvlv.lat
telegram.me/nag0a
dev.epicgames.com/community/api/user_profiles/profile.json?hash_id=EMqJL

# Campaign
Build ID      e53c0776fdba467447b61be1a2bc4027
Marker        o0oi1
Telegram      @nag0a
Epic ID       2036619
Epic hash ID  EMqJL
Epic username nag0a

# Host
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TS_b2f578ca
C:\ProgramData\2365e17917c
AFDSE3esh32le
```

## Useful reverse-engineering locations

These addresses are for the unpacked payload analyzed here:

```text
0x75003976C  embedded config decryption
0x75002CFA0  C2 iteration and initial check-in
0x75002BD3C  dead-drop fetch and marker extraction
0x75002D8BC  ENC hex/XOR decryption
0x75002C310  SHA-256 dead-drop key generation
0x75002EA50  JSON configuration/token parser
0x75002B398  Base64 encoder
0x7500422C0  multipart exfiltration builder
0x750041984  WinHTTP request wrapper
```

## Final thoughts

Vidar 3.2 is not doing anything cryptographically impressive. A repeating XOR protects the embedded configuration, another XOR with a hardcoded SHA-256 digest protects the dead drops, and public profiles provide movable pointers to the real receivers.

The design is still effective. Three independent C2 paths make the campaign easy to move, API hashing slows down a first pass through the binary, and the server controls the useful behavior through flags it only returns after accepting a victim. A sandbox can execute the sample correctly and still see nothing beyond `block`.

For defenders, the stable pieces are the protocol and configuration layout, not any single domain. That is why I built [vidar32-toolkit](https://github.com/AAR072/vidar32-toolkit): point it at an unpacked Vidar 3.2 sample and recover the campaign configuration offline before the infrastructure moves again.
