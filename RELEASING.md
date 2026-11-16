# Releasing

Versions are calendar versions, `YYYY.MMDD.N`: the release date, then a build number that starts at 1
(the first release is `2026.1116.1`). Every manifest carries the version, and the git tag is `v` plus
the version. A version, once published, can never be published again with different content.

To release:

1. Set the new version in `abiz/lib/abiz/version.rb`, `jekyll-abiz/lib/jekyll/abiz/version.rb`, both `CHANGELOG.md` and READMEs, both `Gemfile.lock` files and the `abiz` requirement in `jekyll-abiz.gemspec` and add it to the changelog or README where the old one appears.
2. Merge to `main` with CI green.
3. Tag the merge commit and push the tag: `git tag -a v<version> -m "<version>" && git push origin v<version>`.
4. The tag starts `.github/workflows/release.yml`, which waits for a reviewer to approve the `rubygems` environment, checks the tag against both gems, runs both test suites, builds both gems and pushes `abiz` and then `jekyll-abiz` with credentials from RubyGems trusted publishing (OIDC).

RubyGems trusted publisher, one for each gem (`abiz` and `jekyll-abiz`): repository owner `abiz-org`, repository `abiz-ruby`, workflow `release.yml`, environment `rubygems`. A pending publisher for a gem that does not exist yet expires after about 12 hours, so create it just before pushing the first tag.

Every publishing environment requires a reviewer's approval, and tags matching `v*` are protected.
