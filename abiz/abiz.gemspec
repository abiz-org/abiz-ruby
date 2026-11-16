# frozen_string_literal: true

require_relative "lib/abiz/version"

Gem::Specification.new do |spec|
  spec.name = "abiz"
  spec.version = Abiz::VERSION
  spec.authors = ["ABIZ contributors"]
  spec.summary = "Resolve and check ABIZ (Agentic Business Record) assertions and records."
  spec.description = <<~DESC
    A consumer library for ABIZ 1.1: reads a domain's _abiz DNS TXT assertion (or its
    /.well-known/abiz.json file), fetches the business record it points to through an SSRF-guarded
    HTTPS client, and checks it against the pinned JSON Schema, the semantic rules, the DNS
    assertion and its Ed25519 signature over the RFC 8785 form. It never checks a company register
    and never calls a record's mcp_server_url.
  DESC
  spec.homepage = "https://abizrecord.org"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.1"

  spec.metadata = {
    "homepage_uri" => "https://abizrecord.org",
    "source_code_uri" => "https://github.com/abiz-org/abiz-ruby",
    "bug_tracker_uri" => "https://github.com/abiz-org/abiz-ruby/issues",
    "changelog_uri" => "https://github.com/abiz-org/abiz-ruby/blob/main/abiz/CHANGELOG.md",
    "rubygems_mfa_required" => "true"
  }

  spec.files = Dir[
    "lib/**/*.rb",
    "lib/abiz/data/**/*",
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "NOTICE"
  ].sort
  spec.require_paths = ["lib"]

  # Exact pins (ABIZ library policy): each release is tested against exactly these versions.
  spec.add_dependency "json_schemer", ">= 2.5.0", "< 3"
  spec.add_dependency "simpleidn", ">= 0.3.0", "< 0.4"
  spec.add_dependency "tzinfo", ">= 2.0.6", "< 3"
  spec.add_dependency "tzinfo-data", ">= 1.2026.6", "< 2"
end
