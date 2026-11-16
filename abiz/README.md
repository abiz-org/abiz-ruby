# abiz (Ruby)

A Ruby library for checking ABIZ (Agentic Business Record) records, ABIZ 1.1.

ABIZ is a small open standard. A domain publishes a `_abiz` DNS TXT record
(`v=abiz1;k=…;h=…;p=…`) that points at a signed JSON business record served over HTTPS. This
library is the consumer side: given a domain, it finds the assertion, fetches the record it points
to and checks it, with the same status and error code as the hosted resolver at
`resolve.abizrecord.org`.

- Specification: <https://abizrecord.org> (SPEC.md, ABIZ 1.1)
- Source: <https://github.com/abiz-org/abiz-ruby>
- Licence: Apache-2.0 (the bundled `iso3166.json` is LGPL-2.1; see `NOTICE`)

## Install

```bash
gem install abiz
```

or in a Gemfile:

```ruby
gem "abiz", "2026.1116.1"
```

Ruby 3.1 or later. Runtime dependencies, as ranges from the tested version up to the next major: `json_schemer`
2.5 (JSON Schema 2020-12), `simpleidn` 0.3 (IDNA), `tzinfo` 2 and `tzinfo-data` 1.2026.6 or later
(IANA time zone names). `Gemfile.lock` holds the exact versions the tests run against. Ed25519 comes from Ruby's `openssl`, DNS messages from Ruby's `resolv`, HTTPS from
`net/http`.

## Example

```ruby
require "abiz"

result = Abiz.resolve("harbourbikes.example.org")   # or Abiz.resolve(website: "https://…")
case result.status
when "resolved"
  record = result.record                 # the record exactly as published (a Hash)
  puts record["business_name"]
  puts result.discovery.method           # "dns_txt" or "well_known"
else
  puts "#{result.status}: #{result.code} (retryable: #{result.retryable})"
  result.details.each { |d| puts "  #{d.path}: #{d.message}" }
end
```

## What is checked, and what is not

A result of `resolved` means all of this held:

1. The input is a public domain name (IDN converted to A-labels; URLs, ports, IP literals and
   special-use names such as `.local` refused). `www.` is never removed; the apex is only
   suggested in a `try_apex` warning.
2. One TXT query for `_abiz.<domain>`. NXDOMAIN and NODATA are absence. A timeout, SERVFAIL or
   REFUSED is reported as `unavailable`, never as absence, and the well-known file is not used in
   its place.
3. Exactly one TXT value starts with `v=abiz1` (two or more is `conflict`), and it parses under
   the ABIZ 1.1 tag rules: `h` a host with an optional path, `k` a business key, `p` an Ed25519
   public key in canonical standard base64.
4. Only when DNS answered with no `v=abiz1` value, `https://<domain>/.well-known/abiz.json` is read
   and its `v`, `k`, `h`, `p` members are used exactly as the TXT tags.
5. One GET of `https://<h>?format=json` through the fetch guard (below). No redirect is followed.
6. The body is I-JSON: valid JSON, no repeated member names, at most 64 KiB, depth 16 and 5,000
   members.
7. The record validates against the bundled ABIZ 1.1 JSON Schema (Draft 2020-12, formats asserted)
   and the semantic checks of SPEC sections 4.4 and 4.7.13 (country and region codes, https URLs on
   public names, opening hours, unique ids, prohibited members, and more).
8. `identity_host` equals `h`; `domains` includes the queried domain; `k` (when published) equals
   `business_key`, which agrees with `country` and `registration_number`.
9. `public_key` equals the DNS `p`, and `signature` is a valid Ed25519 signature by that key over
   the RFC 8785 (JCS) form of the record without its top-level `signature`.

What a resolved record is, and is not:

- It is the publisher's own claim, signed with the key that the domain's DNS (or its well-known
  file) vouches for. The library checks that chain. It does not make the business facts true.
- **No company register is checked.** A `business_key` or `registration_number` is the publisher's
  claim. This library says the record was *checked*; it never says a business was *verified*.
- **`mcp_server_url` is never called**, nor any other URL in the record. At most two HTTPS requests
  are made: the well-known file (only when DNS has no assertion) and the record.
- DNSSEC is not validated by this library. The default DNS adapter trusts the system's recursive
  resolver; the DoH adapter trusts its upstream.
- A well-known file shows control of the web server at the domain, which is weaker evidence than
  control of its DNS zone (SPEC section 3.4.5). `result.discovery.method` says which was used.

## The fetch guard

`Abiz::Http::GuardedFetcher` (SPEC section 9): https only, default port, no credentials; local and
private names refused before any lookup; the host's A and AAAA records read first and **every**
address must be public unicast (see `Abiz.public_address?`), else `unsafe_host`; the connection is
made to the checked address (`Net::HTTP#ipaddr=`) while the host name is kept for SNI, certificate
verification and the `Host` header, so the name is not resolved again between the check and the
connection; certificates are verified against the system's roots; no proxy is used (a proxy would
make its own lookup); no redirects; 5 seconds; 64 KiB; `Accept: application/json`;
`User-Agent: abiz-ruby/2026.1116.1 (+https://abizrecord.org)`.

## DNS

Ruby's `Resolv::DNS#getresources` returns an empty list for NXDOMAIN, NODATA, SERVFAIL, REFUSED
and a timeout alike, and applies the search list to relative names. ABIZ must tell absence from
failure, so the default adapter, `Abiz::Dns::Stub`, sends its own queries with
`Resolv::DNS::Message` (standard library) to the system's resolvers from `/etc/resolv.conf` (or
the ones you give), always as absolute names, over UDP with TCP on truncation, 2.5 seconds in
all, and reads the response code itself. `Abiz::Dns::DoH` uses DNS-over-HTTPS JSON
(Cloudflare by default, `dns.google` as an option) where port 53 is blocked.

Both adapters are small: any object with `query_txt(name)` returning an `Abiz::TxtLookup` works as
`dns:`, and any object with `fetch(url)` returning an `Abiz::FetchOutcome` works as `http:` (it
then carries the fetch-guard duty). Use this for a cache, a proxy you trust, or tests.

```ruby
dns = Abiz::Dns::DoH.new(url: Abiz::Dns::DoH::UPSTREAMS[:google])
http = Abiz::Http::GuardedFetcher.new(resolver: dns)
Abiz.resolve("example.com", dns: dns, http: http)
```

## API

| Call | Returns |
| --- | --- |
| `Abiz.resolve(domain)` / `Abiz.resolve(website: url)` | `Abiz::Result`: `status`, `code` (nil when resolved), `message`, `retryable`, `details` (path and message, at most 25), `record` (only when resolved), `discovery` (`method`, `owner`, `dns_value`, `record_url`, `well_known`, `well_known_url`), `warnings` (`content_type`, `try_apex` with `domain`), `domain` |
| `Abiz.parse_assertion(value)` | `Abiz::AssertionResult`: `ok?`, `assertion` (`h`, `k`, `p`, `unknown`) or `code` and `message` |
| `Abiz.check_record(record_text, domain, assertion)` | `nil` when accepted, else the first error code; offline. `check_record_details` also returns the problems |
| `Abiz.verify_signature(record, p)` | `Abiz::Check`: `ok?`, or `code` `public_key_mismatch` / `signature_invalid` |
| `Abiz.canonicalize(value)` | RFC 8785 text (`json_text: true` to canonicalise JSON text) |
| `Abiz.sign_record(record, private_key)` | Producer helper: a copy of the record with `public_key` and `signature` set (32-byte seed or `OpenSSL::PKey`) |
| `Abiz.txt_value(h:, p:, k: nil)`, `Abiz.well_known_document(h:, p:, k: nil)` | Producer helpers for the pointer: the TXT value, and a checked `/.well-known/abiz.json` document |
| `Abiz.normalize_input`, `Abiz.identity_host`, `Abiz.public_key?`, `Abiz.public_address?`, `Abiz.assertion?` | The individual rules |

Statuses: `resolved`, `invalid_input`, `not_found`, `conflict`, `invalid_record`, `unavailable`.
Codes are those of the hosted resolver (for example `missing_txt`, `multiple_txt`, `bad_pointer`,
`invalid_key`, `unsafe_host`, `fetch_failed`, `not_json`, `schema_invalid`,
`identity_host_mismatch`, `domain_not_claimed`, `business_key_mismatch`, `public_key_mismatch`,
`signature_invalid`, `dns_timeout`, `dns_failure`, `upstream_timeout`, `origin_unavailable`).
`retryable` is true only for the last four.

## Conformance

- Implements ABIZ 1.1 (`v=abiz1`), the schema `abiz-business-record-v1.1.schema.json` pinned by
  SHA-256 `3658f17f…ff24`, from `abiz-org/abiz-agentic-business-record` at commit
  `3fb26a34e3cb1402a28352b5071a150e87853d5c`.
- Passes every case of the shared ABIZ test vectors, format 1: `assertions.json`,
  `public-keys.json`, `hosts.json`, `addresses.json`, `jcs.json`, `signing.json`, `records.json`
  and `resolution.json`.

Where this library is stricter than the reference resolver (no vector covers either): a string
holding a lone UTF-16 surrogate is refused when the JSON is read (`not_json`) rather than when it is
canonicalised (`signature_invalid`); and a well-known file with a repeated member name is invalid
rather than read last-one-wins.

## Licence

Apache-2.0. `lib/abiz/data/iso3166.json` is the specification repository's extract of the Debian
iso-codes data and is LGPL-2.1 (`lib/abiz/data/ISO3166-README.md`, `NOTICE`). The schemas are the
specification repository's, unchanged.
