import { describe, expect, test } from "vitest";

import { buildValidationResult } from "../js/dkim-analysis.js";

const VALID_ED25519_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const ZERO_ED25519_FINGERPRINT =
  "66:68:7A:AD:F8:62:BD:77:6C:8F:C1:8B:8E:9F:8E:20:08:97:14:85:6E:E2:33:B3:90:2A:59:1D:0D:5F:29:25";

function checkResult(result, name) {
  return result.checks.find(check => check.check === name);
}

describe("DKIM validation result model", () => {
  test("builds a passing Ed25519 result without the DOM", async () => {
    const result = await buildValidationResult(
      `v=DKIM1; k=ed25519; p=${VALID_ED25519_KEY}`
    );

    expect(result.overall).toBe("PASS");
    expect(result.keyType).toBe("ed25519");
    expect(result.keyInspection.fingerprint).toBe(ZERO_ED25519_FINGERPRINT);
    expect(checkResult(result, "Ed25519 public key")).toMatchObject({
      status: "pass",
      detail: "32 bytes (256 bit)"
    });
    expect(new Set(result.checks.map(check => check.category))).toEqual(
      new Set(["dns", "dkim", "key"])
    );
  });

  test("reports a revoked key in the result model", async () => {
    const result = await buildValidationResult("v=DKIM1; k=rsa; p=");

    expect(result.overall).toBe("FAIL");
    expect(result.pState).toBe("revoked");
    expect(result.keyInspection.fingerprint).toBeNull();
    expect(checkResult(result, "p= public key").detail).toBe("Revoked: p= is empty");
  });

  test("rejects a quoted TXT character-string over 255 octets", async () => {
    const oversizedNotes = "a".repeat(256);
    const logical = `v=DKIM1; n=${oversizedNotes}; p=${VALID_ED25519_KEY}`;
    const result = await buildValidationResult(
      logical,
      {
        rawChunks: [logical],
        chunkOctets: [new TextEncoder().encode(logical).length]
      }
    );

    expect(result.overall).toBe("FAIL");
    expect(checkResult(result, "TXT character-string size")).toMatchObject({
      status: "fail",
      detail: expect.stringContaining("Exceeds the 255-octet limit")
    });
  });

  test("includes DNS metadata and rejects multiple TXT RRs", async () => {
    const chunks = ["v=DKIM1; k=ed25519; ", `p=${VALID_ED25519_KEY}`];
    const result = await buildValidationResult(
      chunks.join(""),
      {
        name: "target._domainkey.example.com",
        txtRrCount: 2,
        dnssec: "Not authenticated (resolver AD=false)",
        rawChunks: chunks,
        cnameChain: [{
          owner: "selector._domainkey.example.com",
          target: "target._domainkey.example.com"
        }]
      }
    );

    expect(result.overall).toBe("FAIL");
    expect(result.info.chunks).toEqual(chunks);
    expect(checkResult(result, "TXT RRs").status).toBe("fail");
    expect(checkResult(result, "CNAME resolution").detail).toBe(
      "1 CNAME hop; final TXT owner target._domainkey.example.com"
    );
  });

  test("includes a provider inferred from a CNAME final owner", async () => {
    const result = await buildValidationResult(
      `v=DKIM1; k=ed25519; p=${VALID_ED25519_KEY}`,
      {
        name: "s1.domainkey.u123.wl.sendgrid.net",
        txtRrCount: 1,
        cnameChain: [{
          owner: "s1._domainkey.example.com",
          target: "s1.domainkey.u123.wl.sendgrid.net"
        }]
      }
    );

    expect(result.providerInference).toEqual({
      id: "twilio-sendgrid",
      name: "Twilio SendGrid",
      confidence: "High",
      evidence: "Final TXT owner s1.domainkey.u123.wl.sendgrid.net"
    });
  });
});
