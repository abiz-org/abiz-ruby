# frozen_string_literal: true

require_relative "abiz/version"

# ABIZ (Agentic Business Record) consumer library, ABIZ 1.1.
#
#   result = Abiz.resolve("harbourbikes.example.org")
#   result.status  # => "resolved", "not_found", "invalid_record", ...
#   result.record  # => the record as published, only when resolved
#
# A resolved record is the publisher's own claim, signed with the key its DNS (or well-known file)
# vouches for. Nothing here checks a company register or calls a record's mcp_server_url.
module Abiz
  USER_AGENT = "abiz-ruby/#{VERSION} (+https://abizrecord.org)"
end

require_relative "abiz/ports"
require_relative "abiz/web_url"
require_relative "abiz/host"
require_relative "abiz/business_key"
require_relative "abiz/assertion"
require_relative "abiz/jcs"
require_relative "abiz/json_text"
require_relative "abiz/signature"
require_relative "abiz/schema"
require_relative "abiz/validate"
require_relative "abiz/address"
require_relative "abiz/resolver"
require_relative "abiz/dns"
require_relative "abiz/http"

module Abiz
  module_function

  # Resolve a domain (or a website address, reduced to its host) to its checked ABIZ record.
  # Exactly one of +domain+ and +website+. +dns+ and +http+ are the adapters (see Abiz::TxtLookup
  # and Abiz::FetchOutcome); by default the system's DNS resolvers and the guarded HTTPS client.
  def resolve(domain = nil, website: nil, dns: nil, http: nil)
    dns ||= Dns::Stub.new
    http ||= Http::GuardedFetcher.new(resolver: dns.respond_to?(:addresses) ? dns : Dns::Stub.new)
    Resolver.new(dns: dns, http: http).resolve(domain: domain, website: website)
  end

  # Parse one _abiz TXT value. Returns an AssertionResult: +assertion+ (h, k, p, unknown) when ok,
  # else +code+ and +message+.
  def parse_assertion(value)
    AssertionParser.parse(value)
  end

  # True when the TXT value's first tag is exactly v=abiz1 (it counts towards the one-record rule).
  def assertion?(value)
    AssertionParser.assertion?(value)
  end

  # Check a record offline, as the resolver does after fetching it: +record_text+ is the body
  # served, +domain+ the domain queried, +assertion+ an Assertion or a TXT value. Returns nil when
  # the record is accepted, else the first failing error code.
  def check_record(record_text, domain, assertion)
    check_record_details(record_text, domain, assertion).first
  end

  # As check_record, returning [code_or_nil, problems].
  def check_record_details(record_text, domain, assertion)
    unless assertion.is_a?(Assertion)
      parsed = AssertionParser.parse(assertion)
      return [parsed.code, [Problem.new(path: "assertion", message: parsed.message)]] unless parsed.ok?

      assertion = parsed.assertion
    end
    Resolver.check_record_text(record_text, domain.to_s.downcase.sub(/\.\z/, ""), assertion)
  end

  # Check a record's public_key against +p+ and its signature (SPEC section 4.6). +record+ is a
  # Hash or the record's JSON text. Returns a Check: ok?, or code public_key_mismatch or
  # signature_invalid.
  def verify_signature(record, p)
    record = JsonText.parse(record) if record.is_a?(String)
    Signature.verify(record, p)
  rescue JsonText::ParseError => e
    Check.new(code: "signature_invalid", path: "$", message: "The record is not I-JSON: #{e.message}.")
  end

  # RFC 8785 canonical JSON of a value (Hash, Array, String, number, true, false, nil), or of JSON
  # text when +json_text+ is true.
  def canonicalize(value, json_text: false)
    JCS.canonicalize(json_text ? JsonText.parse(value) : value)
  end

  # The bytes a record's signature signs: RFC 8785 of the record without its top-level signature.
  def signing_input(record)
    Signature.signing_input(record.is_a?(String) ? JsonText.parse(record) : record)
  end

  # A producer helper: a copy of +record+ (a Hash) with public_key and signature set.
  # +private_key+ is a 32-byte Ed25519 seed or an OpenSSL Ed25519 key. Keep private keys out of
  # source code and logs.
  def sign_record(record, private_key)
    Signature.sign(record, private_key)
  end

  # True when +value+ is an ABIZ p key: canonical standard base64 of 32 bytes.
  def public_key?(value)
    AssertionParser.public_key?(value)
  end

  # The canonical form of an h= value or identity_host, or nil.
  def identity_host(value)
    Host.identity_parts(value)
  end

  # The domain a resolver queries for a domain or website input: [:ok, domain] or
  # [:error, code, message].
  def normalize_input(domain: nil, website: nil)
    Host.normalize_input(domain: domain, website: website)
  end

  # The _abiz TXT value for a pointer: "v=abiz1;k=...;h=...;p=..." (k only when given).
  def txt_value(h:, p:, k: nil)
    ["v=abiz1", (k.nil? ? nil : "k=#{k}"), "h=#{h}", "p=#{p}"].compact.join(";")
  end

  # Build a /.well-known/abiz.json document (SPEC section 3.4.2) from its values and check it as a
  # consumer would: the well-known schema, then the tag rules (the assertion parser). Returns
  # [document, nil] or [nil, code, message]. The document is a pointer only; it carries no key
  # material beyond the public key.
  def well_known_document(h:, p:, k: nil)
    document = { "v" => "abiz1" }
    document["k"] = k unless k.nil?
    document["h"] = h
    document["p"] = p
    problems = Schema.well_known_problems(document)
    unless problems.empty?
      first = problems.first
      return [nil, "schema_invalid", "#{first[:path]}: #{first[:message]}"]
    end
    text, problem = AssertionParser.text_from_well_known(document)
    return [nil, "bad_pointer", problem] if problem

    parsed = AssertionParser.parse(text)
    return [nil, parsed.code, parsed.message] unless parsed.ok?

    [document, nil]
  end

  # True when a fetch may connect to this resolved address.
  def public_address?(address)
    Address.public?(address)
  end
end
