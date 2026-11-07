import { describe, expect, test } from "vitest";

import {
  addRfc6376Checks,
  classifyDkimTags,
  countPChunks,
  decodeBase64Strict,
  extractP,
  formatKeyTypeTag,
  hasDkimPublicKeyTag,
  inspectEd25519PublicKey,
  parseTags,
  parseTxtRecordValue,
  sha256Fingerprint,
  validateNotesTagValue,
  validationOverall
} from "../js/dkim-validation.js";

const VALID_ED25519_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

function rfcChecks(record) {
  const checks = [];
  addRfc6376Checks(checks, parseTags(record));
  return checks;
}

function checkResult(checks, name) {
  return checks.find(check => check.check === name);
}

describe("DKIM tag parsing", () => {
  test("joins quoted TXT character-strings and preserves their boundaries", () => {
    const result = parseTxtRecordValue('"v=DKIM1; k=ed25519; " "p=AAAA"');

    expect(result.logical).toBe("v=DKIM1; k=ed25519; p=AAAA");
    expect(result.chunks).toEqual(["v=DKIM1; k=ed25519; ", "p=AAAA"]);
    expect(result.chunkOctets).toEqual([20, 6]);
  });

  test("keeps a double quote in the decoded logical n= value", () => {
    const result = parseTags('v=DKIM1; n=hello "world"; p=AAAA');

    expect(result.logical).toBe('v=DKIM1; n=hello "world"; p=AAAA');
    expect(result.chunks).toHaveLength(1);
    expect(result.tags.n).toBe('hello "world"');
    expect(result.tags.p).toBe("AAAA");
  });

  test("decodes an escaped quote in quoted TXT presentation", () => {
    const parsed = parseTxtRecordValue('"v=DKIM1; n=hello \\"world\\"; " "p=AAAA"');
    const result = parseTags(parsed.logical, parsed.chunks, parsed.chunkOctets);

    expect(result.tags.n).toBe('hello "world"');
    expect(result.tags.p).toBe("AAAA");
  });

  test("decodes a three-digit decimal TXT escape as one octet", () => {
    const parsed = parseTxtRecordValue('"v=DKIM1; n=hello\\032world; p=AAAA"');
    const result = parseTags(parsed.logical, parsed.chunks, parsed.chunkOctets);

    expect(result.tags.n).toBe("hello world");
    expect(result.chunkOctets).toEqual([30]);
  });

  test("rejects text outside quoted TXT character-strings", () => {
    expect(() => parseTxtRecordValue('"v=DKIM1; p=AAAA" trailing'))
      .toThrow("must contain only quoted character-strings");
  });

  test("rejects an unquoted Record Value input", () => {
    expect(() => parseTxtRecordValue("v=DKIM1; p=AAAA"))
      .toThrow("one or more quoted character-strings");
  });

  test("uses DNS character-string boundaries supplied by the wire parser", () => {
    const chunks = ["v=DKIM1; k=ed25519; ", "p=AAAA"];
    const result = parseTags(chunks.join(""), chunks);

    expect(result.logical).toBe("v=DKIM1; k=ed25519; p=AAAA");
    expect(result.chunks).toEqual(chunks);
    expect(result.tags.p).toBe("AAAA");
  });

  test("preserves tag-name case", () => {
    const result = extractP("v=DKIM1; P=AAAA");

    expect(result.state).toBe("missing");
    expect(result.info.tags.P).toBe("AAAA");
  });

  test("does not treat uppercase P= as the DKIM public-key tag", () => {
    expect(hasDkimPublicKeyTag("v=DKIM1; P=AAAA")).toBe(false);
    expect(hasDkimPublicKeyTag("v=DKIM1; p=AAAA")).toBe(true);
  });

  test("does not count uppercase P= as a p= character-string", () => {
    expect(countPChunks(["v=DKIM1; P=AAAA"])).toBe(0);
    expect(countPChunks(["v=DKIM1; p=AAAA"])).toBe(1);
  });

  test("counts p= chunks even when the tag name is split across a chunk boundary", () => {
    expect(countPChunks(["v=DKIM1; p", "=AAAA"])).toBe(2);
    expect(countPChunks(["v=DKIM1; p=AB", "CD"])).toBe(2);
    expect(countPChunks(["v=DKIM1; ", "p=AAAA"])).toBe(1);
  });

  test("rejects a tag name beginning with a digit", () => {
    const result = parseTags("v=DKIM1; 1test=value; p=AAAA");

    expect(result.fields.find(field => field.name === "1test")?.malformed).toBe(true);
  });

  test("rejects a hyphen in a tag name", () => {
    const result = parseTags("v=DKIM1; x-test=value; p=AAAA");

    expect(result.fields.find(field => field.name === "x-test")?.malformed).toBe(true);
  });

  test("reports a duplicate tag", () => {
    const result = parseTags("v=DKIM1; p=AAAA; p=BBBB");

    expect(result.duplicates).toEqual(["p"]);
  });

  test("rejects an empty tag-list element", () => {
    const result = parseTags("v=DKIM1;; p=AAAA");

    expect(result.fields.some(field => field.malformed)).toBe(true);
  });

  test.each(["\r\n", "\n"])(
    "accepts RFC FWS with %j line endings around tags and within p= Base64",
    lineBreak => {
      const record = `\tv \t= ${lineBreak}\tDKIM1; ${lineBreak}\tp \t= QUFB ${lineBreak}\tQQ==\t`;
      const result = extractP(record);

      expect(result.state).toBe("present");
      expect(result.info.tags.v).toBe("DKIM1");
      expect(result.p).toBe("QUFBQQ==");
    }
  );

  test("does not remove non-breaking space from p= Base64", () => {
    const result = extractP("v=DKIM1; p=QUFB\u00A0QQ==");

    expect(result.p).toBe("QUFB\u00A0QQ==");
    expect(decodeBase64Strict(result.p).ok).toBe(false);
  });

  test("does not treat non-breaking space as FWS in tag syntax", () => {
    const result = parseTags("v=DKIM1;\u00A0p=AAAA");

    expect(result.tags.p).toBeUndefined();
    expect(result.fields.some(field => field.malformed)).toBe(true);
  });
});

describe("RFC 6376 validation", () => {
  test("categorizes every RFC record check as DKIM", () => {
    const checks = rfcChecks("v=DKIM1; h=sha256; k=rsa; s=email; t=s; p=AAAA");

    expect(checks.every(check => check.category === "dkim")).toBe(true);
  });

  test("fails v= tag position when a malformed field precedes it", () => {
    const checks = rfcChecks("=foo;v=DKIM1;p=AAAA");

    expect(checkResult(checks, "v= tag position")).toMatchObject({
      status:"fail",
      detail:"v= is present but is not the first tag"
    });
  });

  test("fails v= tag position when an empty leading element precedes it", () => {
    const checks = rfcChecks(";v=DKIM1;p=AAAA");

    expect(checkResult(checks, "v= tag position")).toMatchObject({
      status:"fail",
      detail:"v= is present but is not the first tag"
    });
  });

  test("passes v= tag position when v= genuinely is first", () => {
    const checks = rfcChecks("v=DKIM1; p=AAAA");

    expect(checkResult(checks, "v= tag position")).toMatchObject({
      status:"pass",
      detail:"First tag"
    });
  });

  test("reports lowercase g= as deprecated instead of unknown", () => {
    const checks = rfcChecks("v=DKIM1; g=*; p=AAAA");

    expect(classifyDkimTags({v:"DKIM1", g:"*", p:"AAAA"})).toEqual({
      deprecated:["g"],
      unknown:[]
    });
    expect(checkResult(checks, "Deprecated tags")).toMatchObject({
      status:"info",
      detail:"g=* is deprecated and ignored"
    });
    expect(checkResult(checks, "Unknown tags").detail).toBe("None");
  });

  test("warns when deprecated g= attempts to restrict identities", () => {
    const checks = rfcChecks("v=DKIM1; g=user*; p=AAAA");

    expect(checkResult(checks, "Deprecated tags")).toMatchObject({
      status:"warn",
      detail:"g=user* is deprecated and ignored; the intended identity restriction is not enforced"
    });
    expect(validationOverall(checks)).toBe("PASS (Warnings)");
  });

  test("keeps uppercase G= as an unknown case-sensitive tag", () => {
    const checks = rfcChecks("v=DKIM1; G=*; p=AAAA");

    expect(checkResult(checks, "Deprecated tags").detail).toBe("None");
    expect(checkResult(checks, "Unknown tags").detail).toBe("G (ignored)");
  });

  test("rejects an explicitly empty k= value", () => {
    const result = checkResult(rfcChecks("v=DKIM1; k=; p=AAAA"), "Key type");

    expect(result.status).toBe("fail");
    expect(result.detail).toBe("k= is present but empty");
  });

  test("accepts k=ed25519", () => {
    const result = checkResult(
      rfcChecks(`v=DKIM1; k=ed25519; p=${VALID_ED25519_KEY}`),
      "Key type"
    );

    expect(result.status).toBe("pass");
  });

  test("explains the h=sha256 hash algorithm", () => {
    const result = checkResult(rfcChecks("v=DKIM1; h=sha256; p=AAAA"), "Hash algorithms");

    expect(result).toMatchObject({
      status:"pass",
      detail:"h=sha256; sha256: SHA-256"
    });
  });

  test("identifies h=sha1 as historic and prohibited", () => {
    const result = checkResult(rfcChecks("v=DKIM1; h=sha1; p=AAAA"), "Hash algorithms");

    expect(result).toMatchObject({
      status:"fail",
      detail:"h=sha1; sha1: SHA-1 (historic; prohibited by RFC 8301)"
    });
  });

  test("warns when h= includes both sha1 and sha256", () => {
    const result = checkResult(
      rfcChecks("v=DKIM1; h=sha1:sha256; p=AAAA"),
      "Hash algorithms"
    );

    expect(result).toMatchObject({
      status:"warn",
      detail:"h=sha1:sha256; sha1: SHA-1 (historic; prohibited by RFC 8301); sha256: SHA-256"
    });
  });

  test("keeps an unrecognized h= extension visible and ignored", () => {
    const result = checkResult(rfcChecks("v=DKIM1; h=sha256:future; p=AAAA"), "Hash algorithms");

    expect(result).toMatchObject({
      status:"pass",
      detail:"h=sha256:future; sha256: SHA-256; future: unrecognized algorithm (ignored)"
    });
  });

  test("explains the s=* service type", () => {
    const result = checkResult(rfcChecks("v=DKIM1; s=*; p=AAAA"), "Service type");

    expect(result).toMatchObject({
      status:"pass",
      detail:"s=*; *: all service types; applies to email"
    });
  });

  test("explains the s=email service type", () => {
    const result = checkResult(rfcChecks("v=DKIM1; s=email; p=AAAA"), "Service type");

    expect(result).toMatchObject({
      status:"pass",
      detail:"s=email; email: electronic mail; applies to email"
    });
  });

  test("keeps an unrecognized s= extension visible and ignored", () => {
    const result = checkResult(rfcChecks("v=DKIM1; s=email:future; p=AAAA"), "Service type");

    expect(result).toMatchObject({
      status:"pass",
      detail:"s=email:future; email: electronic mail; future: unrecognized service type (ignored); applies to email"
    });
  });

  test("explains the default s= service type", () => {
    const result = checkResult(rfcChecks("v=DKIM1; p=AAAA"), "Service type");

    expect(result.detail).toBe(
      "s= omitted; default is * (all service types, including email)"
    );
  });

  test("explains the t=y testing flag", () => {
    const result = checkResult(rfcChecks("v=DKIM1; t=y; p=AAAA"), "Selector flags");

    expect(result).toMatchObject({
      status:"info",
      detail:"t=y; y: testing mode"
    });
  });

  test("explains the t=s strict AUID flag", () => {
    const result = checkResult(rfcChecks("v=DKIM1; t=s; p=AAAA"), "Selector flags");

    expect(result.detail).toBe("t=s; s: AUID (i=) domain must exactly match SDID (d=)");
  });

  test("explains multiple t= flags", () => {
    const result = checkResult(rfcChecks("v=DKIM1; t=y:s; p=AAAA"), "Selector flags");

    expect(result.detail).toBe(
      "t=y:s; y: testing mode; s: AUID (i=) domain must exactly match SDID (d=)"
    );
  });

  test("keeps an unrecognized t= extension flag visible and ignored", () => {
    const result = checkResult(rfcChecks("v=DKIM1; t=future; p=AAAA"), "Selector flags");

    expect(result).toMatchObject({
      status:"info",
      detail:"t=future; future: unrecognized flag (ignored)"
    });
  });

  test("rejects lowercase hexadecimal in an n= escape", () => {
    const result = checkResult(
      rfcChecks("v=DKIM1; n=invalid=2f; p=AAAA"),
      "Notes"
    );

    expect(result.status).toBe("fail");
  });
});

describe("key type display", () => {
  test("shows the rsa default only when k= is omitted", () => {
    expect(formatKeyTypeTag(undefined)).toBe("rsa (default)");
  });

  test("shows an explicitly empty k= value as invalid", () => {
    expect(formatKeyTypeTag("")).toBe("(empty / invalid)");
  });
});

describe("quoted-printable notes", () => {
  test("accepts an uppercase hexadecimal escape", () => {
    expect(validateNotesTagValue("note=20example").ok).toBe(true);
  });

  test("rejects an incomplete escape", () => {
    expect(validateNotesTagValue("note=2").ok).toBe(false);
  });

  test("rejects an unencoded semicolon", () => {
    expect(validateNotesTagValue("note;example").ok).toBe(false);
  });

  test("accepts a semicolon written as the escape =3B", () => {
    expect(validateNotesTagValue("note=3Bexample").ok).toBe(true);
  });

  test("accepts the characters adjacent to the excluded semicolon", () => {
    expect(validateNotesTagValue(":<").ok).toBe(true);
  });
});

describe("public-key encoding", () => {
  test("decodes valid Base64", () => {
    const result = decodeBase64Strict("AA==");

    expect(result.ok).toBe(true);
    expect([...result.bytes]).toEqual([0]);
  });

  test("rejects a non-Base64 character", () => {
    expect(decodeBase64Strict("AA*=").ok).toBe(false);
  });

  test("accepts a 32-byte Ed25519 public key", () => {
    const result = inspectEd25519PublicKey(VALID_ED25519_KEY);

    expect(result.base64Ok).toBe(true);
    expect(result.ed25519Ok).toBe(true);
    expect(result.byteLength).toBe(32);
  });

  test("rejects an Ed25519 public key with the wrong length", () => {
    const result = inspectEd25519PublicKey("AA==");

    expect(result.base64Ok).toBe(true);
    expect(result.ed25519Ok).toBe(false);
    expect(result.byteLength).toBe(1);
  });

  test("formats the SHA-256 fingerprint of decoded p= bytes", async () => {
    await expect(sha256Fingerprint(new Uint8Array([0]))).resolves.toBe(
      "6E:34:0B:9C:FF:B3:7A:98:9C:A5:44:E6:BB:78:0A:2C:78:90:1D:3F:B3:37:38:76:85:11:A3:06:17:AF:A0:1D"
    );
  });
});

describe("overall result", () => {
  test("fails when any validation fails", () => {
    expect(validationOverall([
      { status: "pass" },
      { status: "fail" }
    ])).toBe("FAIL");
  });

  test("reports warnings when no validation fails", () => {
    expect(validationOverall([
      { status: "pass" },
      { status: "warn" }
    ])).toBe("PASS (Warnings)");
  });
});
