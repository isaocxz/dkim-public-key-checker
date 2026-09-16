# DKIM Validation and Implementation

Technical reference for the [DKIM Public Key Checker](README.md). See the README
for usage and result interpretation.

## DNS Name Input

The selector may contain multiple DNS labels. The checker requires one
`_domainkey` label with a selector before it and a signing domain after it. It
also enforces the DNS wire-format limits of 63 octets per label and 255 octets
for the complete name. A single trailing root dot is accepted and removed
before lookup.

## Custom DoH Transport

The custom endpoint must support RFC 8484 GET requests using DNS wire format
and permit browser requests through its CORS policy. Existing query parameters
are preserved, but any existing `dns` parameter is replaced for the request.

## DKIM Key Record

RFC 6376 tags checked by the tool:

| Tag | Meaning | Default |
| --- | --- | --- |
| `v=` | Version | — |
| `h=` | Hash algorithms | all supported |
| `k=` | Key type | `rsa` |
| `n=` | Notes | empty |
| `p=` | Public key | required |
| `s=` | Service type | `*` |
| `t=` | Flags | empty |

Additional checks include tag-list syntax, duplicate tags, `v=` position, missing `p=`, revoked key (`p=` empty), and unknown extension tags.

### Hash Algorithms (`h=`)

The optional `h=` tag restricts the hash algorithms that signatures may use
with the key. The tag allows all algorithms when omitted. `sha256` identifies
SHA-256. `sha1` is retained as a historic registry value but is prohibited for
DKIM signing and verification by RFC 8301. A record restricted to `sha1`
fails validation. A record containing both `sha1` and `sha256` passes with a
warning because SHA-256 remains usable. Unrecognized algorithms are ignored
as extension values.

### Service Types (`s=`)

The optional `s=` tag lists the services for which the key can be used. The
`email` value means electronic mail, and `*` means all service types. The tag
defaults to `*` when omitted. A verifier ignores the record when its service
type is not listed, and ignores individual service values it does not
recognize.

### Selector Flags (`t=`)

The optional `t=` tag modifies how a verifier interprets the selector. The
`y` flag indicates that the domain is testing DKIM. The `s` flag requires the
domain in the signature's AUID (`i=`) to exactly match the signing domain
identifier (`d=`), rather than allowing a subdomain. Multiple flags are
separated by colons, for example `t=y:s`. Unrecognized flags are ignored as
required by RFC 6376.

### Deprecated `g=` Tag

RFC 4871 defined `g=` as an optional restriction on the signing identity's local-part.
RFC 6376 removed that restriction mechanism, deprecated `g=`, and requires
verifiers to ignore it.

The checker reports `g=*` as informational because ignoring it does not remove an
identity restriction. If `g=` contains any other value, the checker reports a
warning: a current verifier ignores the tag, so the identity restriction intended
by the record publisher is not enforced. The record is not rejected solely because
`g=` is present.

### Key-Type Dispatch

After validating the DKIM tags and checking that `p=` contains a public key,
the checker selects the public-key validation path from `k=`.

```text
                 DKIM key record
                        │
                  validate tags
                        │
                   inspect k=
                        │
          ┌─────────────┴─────────────┐
          │                           │
  k=rsa or omitted              k=ed25519
          │                           │
          ▼                           ▼
   RSA validation              Ed25519 validation
```

Omitting `k=` selects `rsa`, as specified by RFC 6376. An empty or unsupported
key type fails validation.

### Public-Key Fingerprint

When `p=` contains valid Base64, the checker displays a SHA-256 fingerprint of
the exact Base64-decoded `p=` bytes. For RSA this hashes the DER-encoded
SubjectPublicKeyInfo; for Ed25519 it hashes the 32-byte raw public key. The
fingerprint is informational and is not a certificate or SSH fingerprint. It
does not prove possession of the private key or verify a DKIM signature.

## RSA Validation

For `k=rsa`, or when `k=` is omitted, `p=` contains a Base64-encoded DER
SubjectPublicKeyInfo structure.

```text
k=rsa or k= omitted
          │
          ▼
     Base64-decode p=
          │
          ▼
 DER SubjectPublicKeyInfo
          │
          ▼
     import RSA key
          │
          ├─ modulus
          ├─ exponent
          └─ key length
```

| RSA key length | Result |
| --- | --- |
| `< 1024 bit` | `FAIL` |
| `1024–2047 bit` | `WARN` |
| `>= 2048 bit` | `PASS` |

This policy follows RFC 8301: RSA keys below 1024 bits are prohibited, and 2048 bits or greater are recommended.

## Ed25519 Validation

RFC 8463 stores an Ed25519 public key directly in `p=` as Base64-encoded raw
key bytes rather than as SubjectPublicKeyInfo (SPKI).

```text
k=ed25519
     │
     ▼
Base64-decode p=
     │
     ▼
raw public-key bytes
     │
     ▼
exactly 32 bytes?
     │
     ├─ yes → PASS
     └─ no  → FAIL
```

The checker strictly decodes Base64 and requires exactly 32 bytes (256 bits).
This validates the DKIM key's encoding and length. It does not decode the
bytes as an RFC 8032 curve point or verify a DKIM message signature.

## DNS and DNSSEC

DNS Lookup mode uses **RFC 8484 DNS wire-format DoH** through the browser Fetch API.

```text
DNS query
 ├─ Header
 ├─ Question
 └─ EDNS(0), DO=1
        │
        ▼
      HTTPS
        │
        ▼
 Recursive resolver
        │
        ▼
DNS response
 ├─ RCODE
 ├─ AD bit
 └─ TXT RR

Auxiliary SOA lookup
 └─ nearest enclosing zone
```

DNSSEC status is based on the recursive resolver's **AD (Authenticated Data)** bit:

| Resolver response | Display |
| --- | --- |
| `AD=1` | Secure |
| `AD=0` | Not authenticated |

The checker does **not** cryptographically validate RRSIG/DNSKEY itself. `AD=0` does not necessarily indicate broken DNSSEC; the zone may simply be unsigned.

### Why DoH?

Browsers cannot send arbitrary UDP/TCP DNS queries to port 53. DoH allows the browser to carry a complete DNS wire-format message over HTTPS without a backend server.

Wire format is used because it preserves details needed by the checker, including TXT RR boundaries, `character-string` boundaries, DNS header flags, EDNS(0)/DO, RCODE, and SOA data.

A TXT RR must contain at least one length-prefixed `character-string`. An empty RDATA is rejected, while one zero-length `character-string` is valid DNS encoding.

When a selector is an alias, the checker processes the CNAME chain and final TXT RRset returned in a single DoH response. If the resolver cannot complete the CNAME chain, the checker does not issue an additional query to retrieve the final TXT RRset. Keeping the result to one response also means that the displayed DNSSEC status uses the AD bit from that response.

Provider inference is documented in [DKIM-PROVIDER-INFERENCE.md](DKIM-PROVIDER-INFERENCE.md).

## Implementation

```text
index.html   → Page structure
styles.css  → Presentation
js/
 ├─ app.js              → UI and lookup orchestration
 ├─ dkim-analysis.js    → Validation result model
 ├─ dkim-dns-response.js → CNAME ordering and final TXT answer selection
 ├─ dkim-fqdn.js        → DKIM DNS name validation
 ├─ dkim-signature.js   → d= and s= extraction for DNS lookup
 ├─ dkim-provider.js    → Provider inference from a CNAME final owner
 ├─ dkim-validation.js  → DKIM and public-key validation
 │    ├─ Web Crypto API → SPKI / RSA
 │    └─ Base64 decoder → Ed25519 raw-key length
 ├─ dns-wire.js         → DNS query encoding and response parsing
 │    └─ Uint8Array / DataView → DNS wire format
 └─ doh-transport.js    → RFC 8484 HTTP transport / Fetch API
```

**No external JavaScript libraries or frameworks are used at runtime.** Vitest
is used only for development-time logic tests.

DNS message encoding and response parsing are implemented directly in JavaScript.

## Standards

- RFC 6376 — DomainKeys Identified Mail (DKIM) Signatures
- RFC 8301 — Cryptographic Algorithm and Key Usage Update to DKIM
- RFC 8463 — A New Cryptographic Signature Method for DKIM
- RFC 8484 — DNS Queries over HTTPS (DoH)
- RFC 6891 — Extension Mechanisms for DNS (EDNS(0))
