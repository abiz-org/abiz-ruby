# frozen_string_literal: true

require_relative "lib/jekyll/abiz/version"

Gem::Specification.new do |spec|
  spec.name = "jekyll-abiz"
  spec.version = Jekyll::Abiz::VERSION
  spec.authors = ["ABIZ contributors"]
  spec.summary = "Publish an ABIZ pointer (/.well-known/abiz.json) from a Jekyll site's _config.yml."
  spec.description = <<~DESC
    A Jekyll generator that writes /.well-known/abiz.json (ABIZ 1.1, SPEC section 3.4) from the
    abiz: { h:, k:, p: } values in _config.yml, after checking them with the abiz gem's assertion
    parser, and fails the build with a clear message when they are invalid. It publishes a pointer
    only and never holds a private key.
  DESC
  spec.homepage = "https://abizrecord.org"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.2"

  spec.metadata = {
    "homepage_uri" => "https://abizrecord.org",
    "source_code_uri" => "https://github.com/abiz-org/abiz-ruby",
    "bug_tracker_uri" => "https://github.com/abiz-org/abiz-ruby/issues",
    "changelog_uri" => "https://github.com/abiz-org/abiz-ruby/blob/main/jekyll-abiz/CHANGELOG.md",
    "rubygems_mfa_required" => "true"
  }

  spec.files = Dir["lib/**/*.rb", "README.md", "CHANGELOG.md", "LICENSE", "NOTICE"].sort
  spec.require_paths = ["lib"]

  spec.add_dependency "abiz", ">= 2026.1116.1", "< 2028"
  # A plugin runs inside the site's own Jekyll, so Jekyll is a range, not a pin; the tests run
  # against the exact version in the Gemfile.
  spec.add_dependency "jekyll", ">= 4.0", "< 5.0"
end
