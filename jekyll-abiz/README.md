# jekyll-abiz

A Jekyll plugin that publishes an ABIZ pointer, `/.well-known/abiz.json` (ABIZ 1.1, SPEC
section 3.4), from your site's `_config.yml`.

ABIZ (Agentic Business Record) lets a domain point at its signed business record. The usual way is
a `_abiz` DNS TXT record; a site that cannot add DNS records can publish the same values as
`https://<your domain>/.well-known/abiz.json` instead. This plugin writes that file, after checking
the values with the [`abiz`](../abiz) gem's own assertion parser, and stops the build with a clear
message if they are wrong.

It publishes a **pointer only**. It never reads, holds or writes a private key, and it refuses
settings that look like one. The business record itself, and its signature, are made elsewhere.

## Install

```ruby
# Gemfile
group :jekyll_plugins do
  gem "jekyll-abiz", "2026.1116.1"
end
```

```yaml
# _config.yml
plugins:
  - jekyll-abiz

abiz:
  h: "records.example.org/acme"                       # the record host (required)
  p: "VWQYaWGhH5gcAwj/7ee6AnHsL1xzNlr4QdScICqIgjc="   # the Ed25519 PUBLIC key (required)
  k: "gb-01234567"                                     # the business key (optional)
  print_txt: true                                      # also log the matching _abiz TXT value
```

`jekyll build` then writes `_site/.well-known/abiz.json`:

```json
{
  "v": "abiz1",
  "k": "gb-01234567",
  "h": "records.example.org/acme",
  "p": "VWQYaWGhH5gcAwj/7ee6AnHsL1xzNlr4QdScICqIgjc="
}
```

With `print_txt: true` the build log also shows the equivalent DNS value,
`v=abiz1;k=gb-01234567;h=records.example.org/acme;p=VWQY…gjc=`, for when you can add DNS later.
If both exist they must say the same thing; DNS takes precedence (SPEC section 3.4.4).

## What is checked

- `h`, `p` and `k` are strings (quote them in YAML), and `h` and `p` are present.
- The document validates against the bundled `abiz-well-known-v1.1.schema.json`.
- The values pass the same tag rules a consumer applies: `h` a host with an optional path (no
  scheme, port, query or fragment; not a special-use name such as `.local`), `k` a business key,
  `p` an Ed25519 public key as 44 characters of canonical standard base64.
- No setting in `abiz:` looks like private key material (`private_key`, `seed`, `secret`, ...).
- No other file is already published at `/.well-known/abiz.json`.

It does not fetch the record at `h`, check its signature, or check a company register.
Use `Abiz.resolve` from the `abiz` gem against the live site to check the whole chain.

## Serving

SPEC section 3.4.3 asks for the file over HTTPS, status 200, no redirect, `Content-Type:
application/json`, at most 65,536 bytes, ideally with `Cache-Control: max-age=300`. Jekyll writes
the file; your host serves it. Check that the host serves `.well-known` (some exclude dot
directories) and sends the JSON content type.

## Licence

Apache-2.0. Tests run against Jekyll 4.4.1; the gem accepts Jekyll 4.x.
