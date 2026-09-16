# DKIM Public Key Checker

[**Open the checker**](https://isaocxz.github.io/dkim-public-key-checker/)

A browser-based tool for mail administrators to inspect and validate DKIM
public-key records through DNS lookup or by pasting a TXT value. It shows
which checks passed or failed to help you investigate configuration problems.

## Why Use This Checker?

| Capability | What this checker provides |
| --- | --- |
| Pre-publication validation | Validate a pasted TXT value before changing DNS, including its syntax, key format, and actual RSA key size. |
| Detailed validation results | Separate DNS, DKIM tag, and public-key results help pinpoint configuration, syntax, or key-data problems. |
| CNAME resolution path | Inspect the CNAME chain and final TXT owner, with likely provider information for recognized targets. |
| TXT record structure | Inspect the strings within each TXT record and detect multiple TXT records at the same selector. |
| Client-side processing | Entirely in your browser. TXT validation happens locally; only DNS lookups send data to the selected resolver. No input is uploaded to an application backend. |

## Usage

Use a current Chrome, Edge, Firefox, or Safari browser and open the checker
using the link above. DNS Lookup mode needs access to the selected
DNS-over-HTTPS (DoH) resolver.

### Look Up a Published Record

1. In **DNS Lookup**, enter the complete DKIM DNS name, for example
   `selector._domainkey.example.com`.
2. Select a resolver and click **Lookup & Validate**.
3. Review the overall result and individual checks.

If you have a message's DKIM-Signature header, choose **DKIM-Signature**,
paste that one header field, and click **Extract & Lookup**. Folded header
lines are accepted. The checker uses its signing domain (`d=`) and selector
(`s=`) to find the public-key record.

Choose **Custom DoH endpoint** to use another compatible HTTPS resolver.
The endpoint must support browser access; see the
[transport requirements](DKIM-VALIDATION.md#custom-doh-transport).
Do not include credentials or other sensitive information in its URL.

After a lookup, you can copy or bookmark the page URL to reuse the DNS name.
Opening a link with the `fqdn` parameter starts a lookup automatically:

```text
https://isaocxz.github.io/dkim-public-key-checker/?fqdn=selector._domainkey.example.com
```

### Check a TXT Value Before or After Publication

1. Select **TXT Record**.
2. Paste the complete DKIM TXT value supplied by your provider or DNS tool.
3. Click **Validate**.

For example, a record begins with `v=DKIM1; k=rsa; p=...`; include the full
public key in place of `...`. Quoted DNS strings are also accepted and joined
without inserting spaces before validation.

This mode works without network access once the page has loaded. It is also
useful when DoH access is unavailable. It cannot confirm what is published in
DNS or report DNS-level information such as TXT record count or DNSSEC status.

## Reading the Results

| Status | Meaning |
| --- | --- |
| `PASS` | The check succeeded. |
| `WARN` | Review the reported security or interoperability concern. |
| `FAIL` | A required validation condition failed. |
| `INFO` | Supplemental information; does not affect the overall result. |

The overall result is **FAIL** if any check fails, **PASS (Warnings)** if
there are warnings but no failures, and **PASS** otherwise. Review the
individual checks for the cause and any required configuration changes.

A passing result covers the public-key record checks performed by this tool.
It does not establish that a message's DKIM signature is valid or that mail
will pass authentication or be delivered.

## Scope and Limitations

- Supports RSA and Ed25519 public-key records. Ed25519 checks cover Base64
  encoding and the required 32-byte raw key length; they do not validate
  whether the bytes represent a valid curve point.
- Does not verify message signatures, body hashes, SPF, or DMARC alignment.
  Pasting a DKIM-Signature header only locates the public-key record.
- DNSSEC status reflects the selected resolver's AD (Authenticated Data) bit.
  The checker does not independently validate DNSSEC signatures. A result of
  **Not authenticated** can mean the zone is unsigned, rather than broken.
- A likely DKIM provider is supplemental information based on a recognized
  CNAME final owner. It does not identify the domain's complete mail platform
  or prove which service sent a message.

## Data Handling

TXT validation and header extraction happen in the browser. Pasted TXT values
and complete DKIM-Signature headers are not uploaded. DNS Lookup mode sends
the requested DNS name and related DNS queries to the selected DoH resolver.
There is no analytics or telemetry.

A lookup puts the checked DNS name in the page URL, so it is visible when that
URL is copied or shared. A custom resolver endpoint is used only for the
current page session and is not stored or added to the page URL.

## Further Documentation

- [Validation rules and implementation](DKIM-VALIDATION.md): DKIM tags,
  public-key checks, DNS handling, and standards.
- [Provider inference](DKIM-PROVIDER-INFERENCE.md): supported patterns and
  evidence used to identify a likely DKIM provider.
- [Testing and regression cases](DKIM-VALIDATION-TEST-CASES.md): test methods,
  DNS fixtures, and expected results.

## License

This project is licensed under the [MIT License](LICENSE).
