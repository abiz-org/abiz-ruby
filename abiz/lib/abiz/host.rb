# frozen_string_literal: true

require_relative "web_url"

module Abiz
  # Host names: the queried domain, a website's host, the h= record host and the URLs a record
  # carries (SPEC sections 3.2 and 4.7.1; the reference validator's safe_host, identity_parts and
  # check_url; the resolver specification's input rules).
  module Host
    HOST = /\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z/
    IPV4ISH = /\A[0-9.]+\z/

    # Suffixes that never name a public business domain. A query for one is refused before any DNS
    # is sent, and a record host under one is never fetched.
    NON_PUBLIC_SUFFIXES = %w[localhost local internal invalid test example onion arpa alt lan home corp intranet private].freeze

    # The special-use and private-use names SPEC section 4.7.1 rules out of a record's URLs. The
    # documentation names .example and .test stay accepted in a record.
    SPEC_NON_PUBLIC_SUFFIXES = %w[localhost local internal home.arpa onion invalid alt].freeze

    # JavaScript's \s (the reference's regular expressions are ECMAScript).
    JS_SPACE = "\\t\\n\\v\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
    JS_DOMAIN_FORBIDDEN = Regexp.new("[#{JS_SPACE}/?#@:\\\\%\\[\\]\"'<>`{}|^]")
    JS_WS_TRIM = Regexp.new("\\A[#{JS_SPACE}]+|[#{JS_SPACE}]+\\z")

    PATH = %r{\A/[\x21-\x7e]*\z}

    module_function

    # A DNS host name as the reference validator accepts it: lower case after folding, dotted, at
    # least two labels, each 1 to 63 characters without a leading or trailing hyphen, at most 253
    # characters, not an IPv4 literal. One trailing dot is allowed.
    def safe_host?(raw)
      return false unless raw.is_a?(String)

      value = raw.downcase.sub(/\.\z/, "")
      return false if !value.match?(HOST) || value.include?("..") || value.length > 253

      labels = value.split(".", -1)
      return false if labels.length < 2
      return false if labels.any? { |l| l.empty? || l.length > 63 || l.start_with?("-") || l.end_with?("-") }
      return false if value.match?(IPV4ISH)

      true
    end

    # True when the host ends in a special-use or private-network suffix, or its top-level label is
    # all digits.
    def non_public_host?(host)
      labels = host.downcase.sub(/\.\z/, "").split(".", -1)
      tld = labels.last || ""
      return true if NON_PUBLIC_SUFFIXES.include?(tld)
      return true if tld.match?(/\A[0-9]+\z/)

      false
    end

    # True when the host is a special-use or private-use name under SPEC section 4.7.1.
    def special_use_name?(host)
      name = host.downcase.sub(/\.\z/, "")
      SPEC_NON_PUBLIC_SUFFIXES.any? { |suffix| name == suffix || name.end_with?(".#{suffix}") }
    end

    # An https URL with a public DNS host name, no credentials, no fragment and the default port
    # (SPEC section 4.7.1). These URLs are checked, never fetched.
    def safe_https_url?(value)
      url = WebUrl.parse(value)
      return false if url.nil? || url.scheme != "https"
      return false if !url.username.empty? || !url.password.empty? || !url.fragment.to_s.empty? || url.port
      return false if url.hostname.start_with?("[")

      safe_host?(url.hostname) && !special_use_name?(url.hostname)
    end

    # An h= value or an identity_host: a host name with an optional path, never a scheme,
    # credentials, port, query or fragment, and no "." or ".." path segment. Returns the canonical
    # form (host lower case, one trailing dot dropped, path as written) or nil.
    def identity_parts(value)
      return nil unless value.is_a?(String) && !value.empty?
      return nil if value.include?("://") || value.match?(Regexp.new("[?#@\\\\#{JS_SPACE}]"))

      slash = value.index("/")
      host = (slash.nil? ? value : value[0...slash]).downcase
      path = slash.nil? ? "" : value[slash..]
      return nil if host.include?(":")
      return nil unless safe_host?(host)

      unless path.empty?
        return nil unless path.match?(PATH)
        return nil if path.split("/", -1).any? { |seg| seg == "." || seg == ".." }
      end
      host.sub(/\.\z/, "") + path
    end

    # The host part of an identity value.
    def identity_hostname(identity)
      slash = identity.index("/")
      slash.nil? ? identity : identity[0...slash]
    end

    # Normalise the resolver's input: exactly one of +domain+ and +website+. Returns
    # [:ok, domain] or [:error, code, message].
    def normalize_input(domain: nil, website: nil)
      has_domain = domain.is_a?(String) && !domain.empty?
      has_website = website.is_a?(String) && !website.empty?
      return [:error, "both_inputs", "Give either domain or website, not both."] if has_domain && has_website
      return normalize_domain(domain) if has_domain
      return domain_from_website(website) if has_website

      [:error, "missing_input", "Give a domain (such as example.com) or a website address."]
    end

    # A queried domain: lower case, IDN to A-labels, one trailing dot dropped. A URL, port,
    # credentials or IP literal is refused. www. is never stripped.
    def normalize_domain(raw)
      trimmed = raw.gsub(JS_WS_TRIM, "")
      return [:error, "invalid_domain", "The domain is empty."] if trimmed.empty?
      return [:error, "invalid_domain", "The domain is longer than 253 characters."] if trimmed.length > 254
      if trimmed.match?(JS_DOMAIN_FORBIDDEN)
        return [:error, "invalid_domain", "Give a host name such as example.com, not a URL. To pass a website address, use the website parameter."]
      end

      host_to_domain(trimmed)
    end

    # The host of an http or https website address, normalised as normalize_domain. The path is
    # ignored.
    def domain_from_website(raw)
      trimmed = raw.gsub(JS_WS_TRIM, "")
      return [:error, "invalid_website", "The website is empty."] if trimmed.empty?
      return [:error, "invalid_website", "The website address is longer than 2048 characters."] if trimmed.length > 2048

      with_scheme = trimmed.match?(/\A[a-z][a-z0-9+.\-]*:/i) ? trimmed : "https://#{trimmed}"
      url = WebUrl.parse(with_scheme)
      return [:error, "invalid_website", "The website is not a valid URL."] if url.nil?
      unless %w[http https].include?(url.scheme)
        return [:error, "invalid_website", "Only http and https website addresses are accepted."]
      end
      unless url.username.empty? && url.password.empty?
        return [:error, "invalid_website", "A website address with a user name or password is refused."]
      end
      return [:error, "invalid_website", "An IP address is not a business domain."] if url.hostname.start_with?("[")

      out = host_to_domain(url.hostname)
      return [:error, "invalid_website", out[2]] if out[0] == :error && out[1] == "invalid_domain"

      out
    end

    def host_to_domain(raw)
      host = raw.sub(/\.\z/, "")
      url = WebUrl.parse("https://#{host}/")
      return [:error, "invalid_domain", "The domain is not a valid host name."] if url.nil?

      host = url.hostname.sub(/\.\z/, "")
      if host.start_with?("[") || host.match?(IPV4ISH)
        return [:error, "invalid_domain", "An IP address is not a business domain."]
      end
      return [:error, "invalid_domain", "The domain is not a valid public host name."] unless safe_host?(host)
      if non_public_host?(host)
        return [:error, "non_public_domain", "The domain ends in a special-use or private-network name, so it has no public ABIZ record."]
      end

      [:ok, host]
    end
    private_class_method :host_to_domain

    # The parent of a www. host, offered as a suggestion only (never resolved in its place).
    def apex_suggestion(domain)
      return nil unless domain.start_with?("www.")

      rest = domain[4..]
      safe_host?(rest) ? rest : nil
    end
  end
end
