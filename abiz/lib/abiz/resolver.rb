# frozen_string_literal: true

require_relative "host"
require_relative "assertion"
require_relative "json_text"
require_relative "schema"
require_relative "validate"
require_relative "signature"
require_relative "ports"

module Abiz
  # One problem found, with where it was found (a JSON Pointer into the record, "$" for the whole
  # record, or the DNS owner name or URL concerned).
  Problem = Struct.new(:path, :message, keyword_init: true)

  # A warning that does not change the status. +code+ is "content_type" or "try_apex"; for
  # try_apex, +domain+ is the apex that might be checked separately (a suggestion, not a result).
  Warning = Struct.new(:code, :message, :domain, keyword_init: true)

  # How the assertion was found.
  #
  # method::         "dns_txt" or "well_known"
  # owner::          the DNS name queried, _abiz.<domain>
  # dns_value::      the v=abiz1 value used, exactly as published (nil when none was used)
  # dns_values::     for multiple_txt, every v=abiz1 value found
  # record_url::     https://<h>?format=json, when it was reached
  # well_known::     "not_checked", "absent", "invalid", "unavailable" or "used"
  # well_known_url:: set when the file was fetched
  Discovery = Struct.new(:method, :owner, :dns_value, :dns_values, :record_url, :well_known, :well_known_url, keyword_init: true)

  # The result of Abiz.resolve.
  #
  # status::    "resolved", "invalid_input", "not_found", "conflict", "invalid_record" or "unavailable"
  # code::      nil when resolved, else the error code
  # message::   a plain-English explanation
  # retryable:: true when trying again later may give another answer
  # details::   Problem list (at most 25)
  # record::    the record as published (a Hash), only when resolved
  # discovery:: a Discovery, or nil when the input was refused before any lookup
  # warnings::  Warning list
  # domain::    the domain queried (as given, when it was refused)
  Result = Struct.new(:status, :code, :message, :retryable, :details, :truncated, :record, :discovery, :warnings, :domain,
                      keyword_init: true) do
    def resolved?
      status == "resolved"
    end
  end

  # The resolution algorithm (SPEC sections 3, 4 and 6; the reference resolver's resolve.ts),
  # free of I/O: DNS and HTTPS go through the adapters it is given.
  class Resolver
    MESSAGES = {
      "missing_input" => "Give a domain (such as example.com) or a website address.",
      "both_inputs" => "Give either domain or website, not both.",
      "invalid_domain" => "The domain is not a valid public host name.",
      "invalid_website" => "The website address is not valid.",
      "non_public_domain" => "The domain is a special-use or private-network name.",
      "missing_txt" => "There is no v=abiz1 TXT record at this name, and /.well-known/abiz.json is missing or invalid, so the domain publishes no ABIZ record.",
      "multiple_txt" => "More than one v=abiz1 TXT record is published at this name. ABIZ treats that as an invalid assertion: the publisher must keep exactly one.",
      "bad_pointer" => "The ABIZ TXT record is malformed.",
      "duplicate_tag" => "The ABIZ TXT record repeats a tag.",
      "missing_h" => "The ABIZ TXT record has no h= tag.",
      "unsafe_host" => "The record host is not a public address this library will fetch.",
      "invalid_key" => "The ABIZ TXT record has no p= key, or a p= value that is not an Ed25519 public key in standard base64.",
      "fetch_failed" => "The record host did not serve the record.",
      "record_too_large" => "The record is larger or more deeply nested than this library accepts (64 KiB, depth 16, 5,000 members).",
      "not_json" => "The record host did not answer with a JSON object (I-JSON: no repeated member names).",
      "schema_invalid" => "The document does not conform to the ABIZ business record schema.",
      "identity_host_mismatch" => "The record's identity_host does not match the DNS h= value.",
      "domain_not_claimed" => "The record's domains list does not include the queried domain.",
      "business_key_mismatch" => "The business key in DNS and the record's registration fields disagree.",
      "public_key_mismatch" => "The record's public_key is not the Ed25519 key published as p= in DNS.",
      "signature_invalid" => "The record's signature is missing or does not verify with its public_key (Ed25519 over the RFC 8785 form of the record without signature).",
      "dns_timeout" => "The ABIZ TXT lookup could not be completed. This does not establish that no ABIZ record exists.",
      "dns_failure" => "The DNS resolver could not answer for this name (for example SERVFAIL). This does not establish that no ABIZ record exists.",
      "upstream_timeout" => "The host did not answer in time. This does not establish that the record is missing.",
      "origin_unavailable" => "The host is temporarily unavailable. This does not establish that the record is missing."
    }.freeze

    RETRYABLE = %w[dns_timeout dns_failure upstream_timeout origin_unavailable].freeze

    STATUS_OF = {
      "missing_input" => "invalid_input", "both_inputs" => "invalid_input", "invalid_domain" => "invalid_input",
      "invalid_website" => "invalid_input", "non_public_domain" => "invalid_input",
      "missing_txt" => "not_found",
      "multiple_txt" => "conflict",
      "dns_timeout" => "unavailable", "dns_failure" => "unavailable", "upstream_timeout" => "unavailable",
      "origin_unavailable" => "unavailable"
    }.freeze

    MAX_DETAILS = 25

    def self.status_of(code)
      STATUS_OF.fetch(code, "invalid_record")
    end

    # SPEC section 4.5: h has no query, so the JSON representation is this exact URL.
    def self.record_url(h)
      "https://#{h}?format=json"
    end

    # SPEC section 3.4.1: the file is on the queried domain, not on h.
    def self.well_known_url(domain)
      "https://#{domain}/.well-known/abiz.json"
    end

    # True for application/json and application/*+json, parameters ignored.
    def self.json_type?(content_type)
      type = content_type.to_s.split(";", 2).first.to_s.strip.downcase
      type == "application/json" || type.match?(%r{\Aapplication/[a-z0-9.+-]+\+json\z})
    end

    def initialize(dns:, http:)
      @dns = dns
      @http = http
    end

    def resolve(domain: nil, website: nil)
      outcome = Host.normalize_input(domain: domain, website: website)
      if outcome[0] == :error
        code = outcome[1]
        shown = domain.is_a?(String) && !domain.empty? ? domain[0, 260] : nil
        return Result.new(status: self.class.status_of(code), code: code, message: outcome[2], retryable: false, details: [],
                          record: nil, discovery: nil, warnings: [], domain: shown)
      end
      resolve_domain(outcome[1])
    end

    # The offline record checks (resolver steps 7 and 8): the record text against the queried
    # domain and the assertion. Returns [nil, []] when accepted, else [code, problems].
    def self.check_record_text(record_text, domain, assertion)
      shape = JsonText.shape_problem(record_text.to_s)
      return ["record_too_large", [Problem.new(path: "$", message: "The record nests deeper than 16 or has more than 5,000 members.")]] if shape

      begin
        value = JsonText.parse(record_text.to_s)
      rescue JsonText::DuplicateMember => e
        return ["not_json", [Problem.new(path: e.pointer.empty? ? "$" : e.pointer,
                                         message: "The record repeats a member name; ABIZ records are I-JSON (RFC 7493), so it is rejected.")]]
      rescue JsonText::ParseError => e
        return ["not_json", [Problem.new(path: "$", message: "The record is not JSON: #{e.message}.")]]
      end
      check_record_value(value, domain, assertion)
    end

    def self.check_record_value(value, domain, assertion)
      schema = Schema.record_problems(value)
      return ["schema_invalid", to_problems(schema)] unless schema.empty?

      conformance, key_problems = Validate.semantic_problems(value)
      identity_ok, domain_ok, link_key = Validate.link_checks(value, domain, assertion)
      key_problems += link_key
      return ["schema_invalid", to_problems(conformance + key_problems)] unless conformance.empty?
      unless identity_ok
        return ["identity_host_mismatch", [Problem.new(path: "/identity_host",
                                                        message: "identity_host must equal the DNS h= value (#{assertion.h}) exactly, path included.")]]
      end
      unless domain_ok
        return ["domain_not_claimed", [Problem.new(path: "/domains", message: "domains must include #{domain}, the domain whose _abiz record points here.")]]
      end
      return ["business_key_mismatch", to_problems(key_problems)] unless key_problems.empty?

      signed = Signature.verify(value, assertion.p)
      return [signed.code, [Problem.new(path: signed.path, message: signed.message)]] unless signed.ok?

      [nil, []]
    end

    def self.to_problems(list)
      list.map { |p| p.is_a?(Problem) ? p : Problem.new(path: p[:path], message: p[:message]) }
    end
    private_class_method :to_problems

    private

    def resolve_domain(domain)
      owner = "_abiz.#{domain}"
      discovery = Discovery.new(method: "dns_txt", owner: owner, well_known: "not_checked")
      warnings = []
      fail = lambda do |code, problems = [], message = nil|
        details = problems.first(MAX_DETAILS)
        Result.new(status: self.class.status_of(code), code: code, message: message || MESSAGES.fetch(code),
                   retryable: RETRYABLE.include?(code), details: details, truncated: problems.length > MAX_DETAILS ? true : nil,
                   record: nil, discovery: discovery, warnings: warnings, domain: domain)
      end

      lookup = @dns.query_txt(owner)
      if lookup.kind == :error
        return fail.call(%i[timeout network].include?(lookup.reason) ? "dns_timeout" : "dns_failure")
      end

      values = lookup.kind == :answer ? Array(lookup.values) : []
      matching = values.select { |v| AssertionParser.assertion?(v) }
      if matching.length > 1
        discovery.dns_values = matching
        return fail.call("multiple_txt")
      end

      if matching.length == 1
        value = matching.first
        discovery.dns_value = value
        parsed = AssertionParser.parse(value)
        return fail.call(parsed.code, [Problem.new(path: owner, message: parsed.message)]) unless parsed.ok?

        assertion = parsed.assertion
      elsif values.any? { |v| AssertionParser.near_miss?(v) }
        return fail.call("bad_pointer", [Problem.new(path: owner,
                                                     message: "A TXT record looks like an ABIZ assertion, but its first tag is not exactly v=abiz1 (check case, spaces and quotes).")])
      else
        assertion, early = well_known_assertion(domain, discovery, warnings, fail)
        return early if early
      end

      url = self.class.record_url(assertion.h)
      discovery.record_url = url
      fetched = @http.fetch(url)
      case fetched.kind
      when :blocked
        return fail.call("unsafe_host", [Problem.new(path: "h", message: fetched.message.to_s)])
      when :no_address
        return fail.call("fetch_failed", [Problem.new(path: "h", message: "The record host has no public A or AAAA address.")])
      when :dns_error
        return fail.call("origin_unavailable", [], "The record host's address could not be looked up. This does not establish that the record is missing.")
      when :timeout
        return fail.call("upstream_timeout")
      when :network
        return fail.call("origin_unavailable", [], "The connection to the record host failed (network or TLS). This does not establish that the record is missing.")
      end

      status = fetched.status.to_i
      if status == 408 || status == 429 || status >= 500
        return fail.call("origin_unavailable", [], "The record host answered HTTP #{status}. This does not establish that the record is missing.")
      end
      if status >= 300 && status < 400
        return fail.call("fetch_failed", [Problem.new(path: "h",
                                                      message: "The record host answered with a redirect (HTTP #{status}). Redirects are not followed: serve the record at the exact h= address.")])
      end
      return fail.call("fetch_failed", [Problem.new(path: "h", message: "The record host answered HTTP #{status}; ABIZ needs 200 with the JSON record.")]) if status != 200
      return fail.call("record_too_large") if fetched.body.nil?

      content_type = fetched.content_type
      if content_type && !content_type.empty? && !self.class.json_type?(content_type)
        type = content_type.split(";", 2).first.to_s.strip.downcase
        if type != "text/plain"
          return fail.call("not_json", [Problem.new(path: "h", message: "The record host answered #{type[0, 80]} to Accept: application/json.")])
        end
      end
      unless content_type && !content_type.empty? && self.class.json_type?(content_type)
        warnings << Warning.new(code: "content_type", message: "The record was served without a JSON content type; it was read as JSON anyway.")
      end

      code, problems = self.class.check_record_text(fetched.body, domain, assertion)
      return fail.call(code, problems) if code

      Result.new(status: "resolved", code: nil, message: "The record resolved and passed every check.", retryable: false, details: [],
                 record: JsonText.parse(fetched.body), discovery: discovery, warnings: warnings, domain: domain)
    end

    # SPEC section 3.4.4 step 5: no v=abiz1 record, so the well-known file may carry the tags.
    # Returns [assertion, nil] or [nil, result].
    def well_known_assertion(domain, discovery, warnings, fail)
      file_url = self.class.well_known_url(domain)
      discovery.well_known_url = file_url
      file = @http.fetch(file_url)
      case file.kind
      when :timeout
        discovery.well_known = "unavailable"
        return [nil, fail.call("upstream_timeout")]
      when :network, :dns_error
        discovery.well_known = "unavailable"
        return [nil, fail.call("origin_unavailable", [], "The well-known file could not be fetched. This does not establish that no ABIZ record exists.")]
      end
      status = file.kind == :response ? file.status.to_i : nil
      if status && (status == 408 || status == 429 || status >= 500)
        discovery.well_known = "unavailable"
        return [nil, fail.call("origin_unavailable", [], "The well-known file host answered HTTP #{status}. This does not establish that no ABIZ record exists.")]
      end

      from_file = nil
      invalid = nil
      if status == 200
        if file.body.nil?
          invalid = "The well-known file is larger than this library accepts (64 KiB)."
        elsif !self.class.json_type?(file.content_type)
          invalid = "The well-known file was not application/json."
        else
          document = parse_small_json(file.body)
          if document == :invalid
            invalid = "The well-known file is not JSON."
          else
            text, problem = AssertionParser.text_from_well_known(document)
            if problem
              invalid = problem
            else
              parsed = AssertionParser.parse(text)
              if parsed.ok?
                from_file = parsed.assertion
              else
                invalid = parsed.message
              end
            end
          end
        end
      end

      if from_file.nil?
        discovery.well_known = invalid ? "invalid" : "absent"
        apex = Host.apex_suggestion(domain)
        if apex
          warnings << Warning.new(code: "try_apex", domain: apex,
                                  message: "Nothing is published at _abiz.#{domain}. #{apex} was not checked and is a different domain; query it separately if that is the business's domain.")
        end
        problems = invalid ? [Problem.new(path: file_url, message: invalid)] : []
        return [nil, fail.call("missing_txt", problems)]
      end

      discovery.method = "well_known"
      discovery.well_known = "used"
      [from_file, nil]
    end

    def parse_small_json(text)
      return :invalid if JsonText.shape_problem(text)

      JsonText.parse(text)
    rescue JsonText::ParseError
      :invalid
    end
  end
end
