# abiz-ruby

Ruby libraries for ABIZ (Agentic Business Record), ABIZ 1.1. One repository, two gems:

| Directory | Gem | What it is |
| --- | --- | --- |
| [`abiz/`](abiz/) | `abiz` | The consumer library: resolve a domain's `_abiz` assertion, fetch its record through a guarded HTTPS client, check the schema, the semantic rules, the DNS link and the Ed25519 signature. |
| [`jekyll-abiz/`](jekyll-abiz/) | `jekyll-abiz` | A Jekyll generator that publishes `/.well-known/abiz.json` from `_config.yml`, checked with `abiz`. |

Both are Apache-2.0 (see `LICENSE` and `NOTICE`), version 2026.1116.1. How they are released: [`RELEASING.md`](RELEASING.md).

## Develop

```bash
cd abiz && bundle config set --local path vendor/bundle && bundle install && bundle exec rake test
cd ../jekyll-abiz && bundle config set --local path vendor/bundle && bundle install && bundle exec rake test
```

The `abiz` tests read the shared vectors from `test-vectors/` at the repository root; set
`ABIZ_VECTORS` to point elsewhere.
