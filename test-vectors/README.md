# ABIZ test vectors (format 1)

One set of cases every ABIZ library runs, so that every library gives the same answer as the hosted resolver (`resolve.abizrecord.org`) and the spec repository's reference validator (`scripts/validate.py`). The rules for implementers are in `IMPLEMENTING.md` at the root of this repository.

| File | What it checks |
| --- | --- |
| `assertions.json` | The `_abiz` TXT value: whether it counts as an assertion, whether it parses, the error code, and the canonical `h`, `k`, `p` |
| `public-keys.json` | The `p` tag and record `public_key`: canonical standard base64 of 32 bytes |
| `hosts.json` | `identity`: an `h` or `identity_host` and its canonical form. `inputs`: the domain a resolver queries for a given domain or website |
| `addresses.json` | Which resolved addresses a fetch may connect to |
| `jcs.json` | RFC 8785 canonical JSON, byte for byte |
| `signing.json` | The signing input of a record, whether it verifies, and two **public** test keys |
| `records.json` | A record checked offline against a domain and an assertion: accepted (`null`) or the first failing code |
| `resolution.json` | The whole algorithm against a fake DNS and a fake fetch: status, code, discovery, warnings and the requests made |

`schemas/` and `data/iso3166.json` are the files the libraries bundle:

| File | SHA-256 |
| --- | --- |
| `schemas/abiz-business-record-v1.1.schema.json` | `3658f17f00c238b8c948fdfb447b509c5d055dd778ebd335495da05c3150ff24` |
| `schemas/abiz-well-known-v1.1.schema.json` | `5fe7da6fb5b6b262281402ab9dd9b46c018bf9df766203928e4e1a334cc3d741` |
| `data/iso3166.json` | `0aa5112c46bc2b3efb254ea9536b3cf2977c73d48149aefcd8bc20df995e5527` |

They are copied unchanged from `abiz-org/abiz-agentic-business-record` at commit `3fb26a34e3cb1402a28352b5071a150e87853d5c` (tag `v1.1.0` and later). `data/iso3166.json` is LGPL-2.1, not Apache-2.0: see `data/README.md`.

## The test keys

`signing.json` lists two Ed25519 keys whose seeds are published there on purpose. They sign test records only. A record signed with either is a test record; never publish one, and never sign anything real with them.

## How they are made

The vectors are generated from the reference resolver (the code behind `resolve.abizrecord.org`) and the spec repository's examples, then cross-checked against `validate.py`; any disagreement fails generation. The output is deterministic (Ed25519 signatures are). This directory is a read-only copy: do not edit it by hand; take a new copy when the vectors change.

## Where the two references differed (16 November 2026)

- **A record URL on a private name** (`https://intranet.local`). SPEC §4.7.1 and `validate.py` reject it; the resolver accepted it. Fixed in the resolver in the same change that added these vectors.
- **A non-ASCII path in `h` or `identity_host`** (`record.example.org/café`). The resolver refuses it, `validate.py` accepts it, and SPEC §3.2 does not say. Left out of the vectors until the spec decides.
- **`h` on a documentation name** (`.example`, `.test`). SPEC §4.7.1 accepts them in a record; the resolver will not fetch from them (`unsafe_host`), as it will not query a domain under them (`non_public_domain`). The vectors follow the resolver for what is fetched and queried, and the spec for what a record may contain.
