# Implementing an ABIZ library

Every ABIZ reference library does the same job in its own language: given a domain, find its `_abiz` assertion, fetch the business record it points to, and say whether the record is valid, with the same status and error code as the hosted resolver at `resolve.abizrecord.org`. The rules are SPEC.md (ABIZ 1.1); the behaviour is fixed by the shared test vectors in [`test-vectors/`](./test-vectors/README.md). A library is conformant when it passes every vector.

No library needs a DNS change: `_abiz` is a plain TXT record, so each language's ordinary DNS client reads it.

## The pipeline

1. **Input.** A domain, or a website address reduced to its host. Lower case, IDN to A-labels, one trailing dot dropped. A URL, port, credentials or IP literal is `invalid_domain` (`invalid_website` for a website); a special-use or private-network name is `non_public_domain`. `www.` is never stripped: the apex is only suggested (`try_apex` warning). Vectors: `hosts.json` `inputs`.
2. **DNS.** One TXT query for `_abiz.<domain>`. Join a record's character-strings with nothing between them. NXDOMAIN and NODATA are absence; a timeout or network failure is `dns_timeout`, SERVFAIL, REFUSED or a malformed answer `dns_failure`. A failure is never treated as absence, and never falls back to the well-known file.
3. **Select.** Count the TXT values whose first tag is exactly `v=abiz1` (`assertions.json` `is_assertion`). Two or more: `multiple_txt`. One: parse it (step 4); if it is malformed the result is invalid and the well-known file is **not** used. None, but a value that looks like an attempt (`V=ABIZ1`, `v=abiz2`): `bad_pointer`.
4. **Parse the assertion** (SPEC §3.1–§3.3, `assertions.json`): DKIM-style tag list, SP/HTAB around `;` and `=`, at most one trailing `;`, `v=abiz1` first, recognised tags `v h k p` (case-sensitive) at most once (`duplicate_tag`), unknown tags ignored. `h` required (`missing_h`) and a host with an optional path (`bad_pointer`), not a special-use name (`unsafe_host`). `k` a business key (`bad_pointer`). `p` required and a canonical 44-character standard base64 Ed25519 key (`invalid_key`).
5. **Well-known fallback** (SPEC §3.4), only when DNS answered with no `v=abiz1` value: GET `https://<domain>/.well-known/abiz.json`. 200 with a JSON content type and a valid document: its `v k h p` members are the assertion. 408, 429 or 5xx, a timeout or a network failure: `unavailable` (`upstream_timeout` or `origin_unavailable`). Anything else (404, a redirect, not JSON, invalid members, over 64 KiB): `missing_txt`.
6. **Fetch the record:** one GET of `https://<h>?format=json` with `Accept: application/json`. Never follow a redirect. Results in order: SSRF guard refused it `unsafe_host`; no public A/AAAA `fetch_failed`; name lookup failed `origin_unavailable`; timeout `upstream_timeout`; connection or TLS failure `origin_unavailable`; 408, 429, 5xx `origin_unavailable`; 3xx or any other non-200 `fetch_failed`; body over 64 KiB `record_too_large`; a content type that is neither JSON (`application/json`, `application/*+json`) nor `text/plain` `not_json`; `text/plain` or no content type is read with a `content_type` warning.
7. **Parse the record** as I-JSON: not JSON, or a repeated member name anywhere, is `not_json`; nesting deeper than 16 or more than 5,000 members is `record_too_large`.
8. **Check the record**, first failure wins (`records.json`): JSON Schema 2020-12 against the bundled schema, then the semantic checks (below), both `schema_invalid`; `identity_host` must equal `h` exactly after canonicalising both (`identity_host_mismatch`); `domains` must include the queried domain, compared lower case without a trailing dot (`domain_not_claimed`); `k`, when present, must equal `business_key` case-insensitively, and `business_key` must agree with `country` and `registration_number` (`business_key_mismatch`); `public_key` must equal `p` exactly (`public_key_mismatch`); `signature` must verify (`signature_invalid`).
9. **Signature** (SPEC §4.6, `signing.json`, `jcs.json`): PureEd25519 over the UTF-8 bytes of the RFC 8785 (JCS) form of the record with only its top-level `signature` member removed.
10. **Never** contact `mcp_server_url` or any other URL in the record, and never fetch more than the one well-known file and the one record.

### Semantic checks (what JSON Schema cannot express)

These follow `validate.py` and the reference resolver and are all reported as `schema_invalid`:

- `identity_host` canonical; every `domains` entry a DNS host name.
- `country.code`, every `locations[].address.country.code`, service-area and tax `jurisdiction` codes assigned in `data/iso3166.json` and not unsupported (`KP`); region codes `CC-XXX` with `CC` matching the country, and assigned for `US`, `CA`, `AE`.
- Every URL member (SPEC §4.7.1): `https`, a DNS host name that is not a special-use name (`localhost`, `.local`, `.internal`, `.home.arpa`, `.onion`, `.invalid`, `.alt`; `.example` and `.test` are accepted), no credentials, no fragment, no port.
- `recent_posts`, `contact_email` and `contact_phone` nowhere in the record, extensions included; no flat `street`, `city`, `postal_code` on a location.
- Opening hours: IANA time zone; days and dates not repeated; periods in order of `opens`, not of zero length, not overlapping, overnight periods included (a Sunday overnight meets Monday).
- `geo` needs `address.street_lines`, and coordinates in range.
- Unique `location_id`, `media[].id`, `media[].position`, review `platform` per holder, tax registration (jurisdiction, scheme, number); `rating` ≤ `rating_scale`; an image needs `alt_text` unless `decorative`; `verification_expires_at` later than `verified_at`.
- `business_key` parses (SPEC §4.2) and agrees with `country` and `registration_number` (reported as `business_key_mismatch`, step 8).

## The fetch guard (SPEC §9)

Resolve the host, refuse unless **every** address is public unicast (`addresses.json`), then connect to a checked address, not the name again (no DNS rebinding window). HTTPS only, port 443, certificate verified, no redirects, 5 s timeout, 64 KiB cap, `Accept: application/json`, a `User-Agent` naming the library and its version.

## The API every library offers

Names follow each language's conventions; the shape is the same.

| Function | Returns |
| --- | --- |
| `resolve(domain)` / `resolve(website=…)` | A result: `status` (`resolved`, `invalid_input`, `not_found`, `conflict`, `invalid_record`, `unavailable`), `code` (null when resolved), `message`, `retryable`, `details` (path and message, at most 25), `record` (only when resolved), `discovery` (`method` `dns_txt` or `well_known`, `owner`, `dns_value`, `record_url`, `well_known`), `warnings` (`content_type`, `try_apex` with `domain`) |
| `parse_assertion(value)` | The assertion (`h`, `k`, `p`, unknown tags) or an error code |
| `check_record(record_text, domain, assertion)` | `null` or the error code, offline (`records.json`) |
| `verify_signature(record, p)` | ok, `public_key_mismatch` or `signature_invalid` |
| `canonicalize(value)` | RFC 8785 text |
| `sign_record(record, private_key)` | A producer helper: the record with `public_key` and `signature` set |

DNS and HTTP sit behind small interfaces (a TXT lookup and a fetch, with the outcomes listed in `resolution.json`) so the vectors run without a network, and so a caller can supply DNS-over-HTTPS, a proxy or a cache.

## Tests

Each library loads the vector files from its copy of the shared vectors (`test-vectors/`, `testdata/test-vectors/` in Go) and runs every case:

- `assertions.json`, `public-keys.json`, `hosts.json`, `addresses.json`, `jcs.json`, `signing.json`: exact.
- `records.json`: `check_record` returns `expect`.
- `resolution.json`: with the stub DNS and fetch, `status`, `code`, `retryable`, `method`, `well_known`, `dns_value`, `domain`, the warning codes and `record_returned` match, and the library makes no request outside `expect.dns_queries` and `expect.fetches`.

A library MUST NOT edit a vector to pass it. A disagreement is a bug in the library, or a question for the spec: raise it.

## Packaging

Apache-2.0, with `NOTICE`. The bundled `iso3166.json` keeps its own LGPL-2.1 notice (`test-vectors/data/README.md`). Version `2026.1116.1` (Go module: `v0.1.0`). Every library bundles the schema and `iso3166.json`, pinned by SHA-256, and states the ABIZ revision it implements (1.1).
