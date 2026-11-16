# Changelog

## 2026.1116.1

First version. Implements ABIZ 1.1 and passes the shared test vectors, format 1.

- `Abiz.resolve`, `Abiz.parse_assertion`, `Abiz.check_record`, `Abiz.verify_signature`,
  `Abiz.canonicalize`, `Abiz.sign_record`, `Abiz.txt_value`, `Abiz.well_known_document`.
- DNS adapters: `Abiz::Dns::Stub` (system resolvers, response codes kept apart) and
  `Abiz::Dns::DoH` (DNS-over-HTTPS JSON).
- `Abiz::Http::GuardedFetcher`, the SPEC section 9 fetch guard.
- Bundled, SHA-256 pinned: the ABIZ 1.1 record and well-known schemas and `iso3166.json`.
