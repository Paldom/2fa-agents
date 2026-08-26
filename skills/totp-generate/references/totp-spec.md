# TOTP reference: RFC 6238, otpauth URIs, and what breaks in practice

**Contents:** [Algorithm](#algorithm) · [Parameters and defaults](#parameters-and-defaults) ·
[otpauth:// URI format](#otpauth-uri-format) · [Test vectors](#rfc-6238-test-vectors) ·
[Verifier behavior you must plan for](#verifier-behavior-you-must-plan-for) ·
[Failure modes](#failure-modes) · [Non-TOTP variants](#non-totp-variants) · [Sources](#sources)

## Algorithm

TOTP is HOTP with a time-derived counter.

```
T    = floor((current_unix_time - T0) / X)
TOTP = HOTP(K, T)
HOTP = truncate(HMAC-<alg>(K, T_as_8_byte_big_endian)) mod 10^digits
```

The truncation is RFC 4226 §5.3 *dynamic truncation*: take the low nibble of the last
HMAC byte as an offset, read 4 bytes at that offset, mask the top bit
(`& 0x7fffffff`), then `mod 10^digits`, zero-padded on the left.

Zero-padding matters: `str(value % 10**6)` alone produces `"51234"` for a code that
must be sent as `"051234"`. Every implementation that drops the leading zero fails
roughly 1 login in 10.

## Parameters and defaults

| Parameter | Default | Notes |
| --- | --- | --- |
| `X` (period) | 30 s | RFC 6238 §4.1 default. 60 s appears in the wild (some banks). |
| `T0` | 0 (Unix epoch) | Practically never overridden. |
| `digits` | 6 | RFC allows 6–8; the URI's `digits=` wins. |
| algorithm | HMAC-SHA1 | SHA-256 / SHA-512 are legal and rare. SHA-1 here is **not** a weakness: HMAC-SHA1 is unaffected by SHA-1 collision attacks. |
| secret encoding | Base32, RFC 4648 | Displayed lowercase and space-grouped by most apps; padding usually stripped. |

The secret is raw bytes. Base32 is only a transport encoding — a 20-byte secret is 32
base32 characters, a 16-byte secret is 26 characters plus padding.

## otpauth:// URI format

The de-facto spec is Google's Key Uri Format wiki page (there is no RFC).

```
otpauth://totp/LABEL?secret=BASE32&issuer=Example&algorithm=SHA1&digits=6&period=30
```

- `TYPE` is `totp` or `hotp`. **`hotp` is counter-based** — it needs persistent counter
  state and a resync window; a time-only generator cannot produce valid HOTP codes.
- `LABEL` is `issuer:accountname`, percent-encoded; the colon may appear as `%3A`.
  Neither part may itself contain a colon.
- `secret` is required; everything else has a default.
- `issuer` should match the label prefix when both are present. Older Google
  Authenticator versions ignore `issuer`, `algorithm`, and `period` — so a URI that
  renders correctly in one app can silently produce wrong codes in another. When a code
  is rejected but the secret is right, compare `digits`/`period`/`algorithm` first.

## RFC 6238 test vectors

Appendix B, all **8 digits**. The Appendix A reference implementation uses a *different
seed per algorithm* even though the Appendix B table prints one label — this is the most
common reason a hand-written implementation "fails" the SHA-256/SHA-512 vectors:

| Algorithm | Seed (ASCII) | Bytes |
| --- | --- | --- |
| SHA-1 | `12345678901234567890` | 20 |
| SHA-256 | `12345678901234567890123456789012` | 32 |
| SHA-512 | `1234567890123456789012345678901234567890123456789012345678901234` | 64 |

| Unix time | SHA-1 | SHA-256 | SHA-512 |
| --- | --- | --- | --- |
| 59 | 94287082 | 46119246 | 90693936 |
| 1111111109 | 07081804 | 68084774 | 25091201 |
| 1111111111 | 14050471 | 67062674 | 99943326 |
| 1234567890 | 89005924 | 91819424 | 93441116 |
| 2000000000 | 69279037 | 90698825 | 38618901 |
| 20000000000 | 65353130 | 77737706 | 47863826 |

`scripts/totp.py --selftest` runs this table plus a base32-formatting check.

## Verifier behavior you must plan for

- **One use per time step.** RFC 6238 §5.2: "The verifier MUST NOT accept the second
  attempt of the OTP after the successful validation has been issued for the first OTP."
  Conformant servers therefore reject a *replay* of an already-accepted code. Servers
  vary in whether a code that was merely *submitted and rejected* is burned, so the safe
  retry rule is the same either way: **never resubmit the same digits — wait for the next
  window.**
- **Acceptance window.** RFC 6238 §5.2 recommends "at most one time step" of tolerance
  for network delay. Many servers accept ±1 step (a 90 s span); some accept exactly one.
  Never rely on tolerance to cover your own latency.
- **Clock drift** is the single most common cause of "the code is always wrong". Your
  clock, not theirs, is usually the problem. Check before debugging anything else:
  `sntp -t 5 time.apple.com` (macOS) or `chronyc tracking` / `timedatectl` (Linux).
  Drift over ~±30 s breaks every code.

## Failure modes

| Symptom | Cause |
| --- | --- |
| Code always rejected, secret confirmed correct | Clock drift; or `digits`/`period`/`algorithm` mismatch with the issuer |
| `binascii.Error: Incorrect padding` | Base32 padding computed **before** stripping spaces/hyphens. Strip separators first, `rstrip("=")`, then re-pad to a multiple of 8 |
| Code has 5 letters, not 6 digits | Steam (`encoder=steam`) — different output alphabet, see below |
| Works locally, fails in CI | CI runner clock, or the code was generated at the start of a slow test and submitted after the window rolled |
| Retry after "invalid code" also fails | Same code resubmitted inside one window — wait for the next |
| `0`/`O` or `1`/`l` in a transcribed secret | Base32 (RFC 4648) has no `0`, `1`, `8`, or `9`; those characters are always transcription errors |

## Non-TOTP variants

- **Steam Guard**: `encoder=steam` in the URI. Same HMAC-SHA1 dynamic truncation, but the
  31-bit value is rendered in base-26 over `23456789BCDFGHJKMNPQRTVWXY`, 5 characters.
  Steam's own `shared_secret` field is **base64**, not base32 — convert before use.
- **HOTP** (`otpauth://hotp/…`): counter-based; requires storing and incrementing a
  counter, and a server-side look-ahead window. Out of scope for a time-based generator.
- **`otpauth-migration://offline?data=…`**: Google Authenticator's export QR. Base64 of an
  undocumented, reverse-engineered protobuf. Treat the schema as unstable; decode it once
  into per-account `otpauth://` URIs and keep those instead.

## Sources

- RFC 6238 (TOTP) — <https://www.rfc-editor.org/rfc/rfc6238>
- RFC 4226 (HOTP, dynamic truncation §5.3) — <https://www.rfc-editor.org/rfc/rfc4226>
- RFC 4648 (Base32) — <https://www.rfc-editor.org/rfc/rfc4648>
- Key Uri Format — <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
- `oathtool(1)` — <https://www.nongnu.org/oath-toolkit/man-oathtool.html>
