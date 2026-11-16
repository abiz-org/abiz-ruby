# frozen_string_literal: true

require_relative "host"
require_relative "business_key"

module Abiz
  # A parsed _abiz assertion (SPEC sections 3.1 to 3.3). +h+ is the canonical record host (host
  # lower case, path as published), +k+ the business key as published or nil, +p+ the Ed25519
  # public key in standard base64, +unknown+ the tags the specification does not define.
  Assertion = Struct.new(:h, :k, :p, :unknown, keyword_init: true)

  # The outcome of Abiz.parse_assertion: +assertion+ when ok, else +code+ (bad_pointer,
  # duplicate_tag, missing_h, unsafe_host or invalid_key) and +message+.
  AssertionResult = Struct.new(:assertion, :code, :message, keyword_init: true) do
    def ok?
      code.nil?
    end
  end

  # The _abiz TXT assertion: selecting it, parsing its tag list and checking its p key.
  module AssertionParser
    JS_SPACE = Host::JS_SPACE
    RECOGNISED = %w[v h k p].freeze
    WSP_TRIM = /\A[ \t]+|[ \t]+\z/
    # Controls other than HTAB, DEL, and any non-WSP Unicode space.
    FORBIDDEN = Regexp.new("[\\u0000-\\u0008\\u000a-\\u001f\\u007f]|(?![ \\t])[#{JS_SPACE}]")
    # JavaScript's \s without the controls, which the classes below list themselves.
    JS_SPACE_NONCTRL = " \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
    TAG_NAME = Regexp.new("\\A[^#{JS_SPACE_NONCTRL};=\\u0000-\\u001f\\u007f]+\\z")
    TAG_VALUE = Regexp.new("\\A[^#{JS_SPACE_NONCTRL};\\u0000-\\u001f\\u007f]+\\z")
    STD_BASE64_KEY = %r{\A[A-Za-z0-9+/]{43}=\z}
    ASSERTION = /\A[ \t]*v[ \t]*=[ \t]*abiz1[ \t]*(;|\z)/
    NEAR_MISS = Regexp.new("\\A[#{JS_SPACE}]*\"?[#{JS_SPACE}]*v[#{JS_SPACE}]*=[#{JS_SPACE}]*abiz", Regexp::IGNORECASE)

    module_function

    # True when the value's first tag is exactly v=abiz1 (SPEC section 3.1.1), so it counts towards
    # the one-record rule. V=ABIZ1, v=abiz1x and h=...;v=abiz1 do not.
    def assertion?(value)
      value.is_a?(String) && value.match?(ASSERTION)
    end

    # Looks like an attempt at an assertion, but the first tag is not v=abiz1.
    def near_miss?(value)
      value.is_a?(String) && !assertion?(value) && value.match?(NEAR_MISS)
    end

    # True when +value+ is an ABIZ 1.1 p key: 44 characters of canonical standard base64 ending in
    # one "=", decoding to 32 bytes.
    def public_key?(value)
      return false unless value.is_a?(String) && value.match?(STD_BASE64_KEY)

      bytes = value.unpack1("m0")
      bytes.bytesize == 32 && [bytes].pack("m0") == value
    rescue ArgumentError
      false
    end

    def trim_wsp(text)
      text.gsub(WSP_TRIM, "")
    end
    private_class_method :trim_wsp

    # Split a value into [name, value] tags under the ABIZ 1.1 tag-list syntax. Returns
    # [tags, nil] or [nil, message].
    def tag_list(value)
      if value.match?(FORBIDDEN)
        return [nil, "The ABIZ TXT value contains a line break, control character or non-ASCII space. Only spaces and tabs are allowed, and only around \";\" and \"=\"."]
      end

      body = trim_wsp(value)
      body = trim_wsp(body[0...-1]) if body.end_with?(";")
      tags = []
      body.split(";", -1).each do |raw|
        part = trim_wsp(raw)
        eq = part.index("=")
        if eq.nil? || eq.zero?
          return [nil, "Every tag must be name=value (found \"#{clip(part)}\"). An empty tag (\";;\") or more than one trailing \";\" is invalid."]
        end

        name = trim_wsp(part[0...eq])
        val = trim_wsp(part[(eq + 1)..])
        if !name.match?(TAG_NAME) || val.empty?
          return [nil, "Every tag must be name=value with both parts present (found \"#{clip(part)}\")."]
        end
        unless val.match?(TAG_VALUE)
          return [nil, "A tag value must not contain whitespace (found \"#{clip(part)}\"). Spaces are allowed only around \";\" and \"=\"."]
        end

        tags << [name, val]
      end
      first = tags.first
      return [nil, "The first tag must be v=abiz1."] if first.nil? || first[0] != "v" || first[1] != "abiz1"

      [tags, nil]
    end

    # Parse one v=abiz1 value under ABIZ 1.1 (SPEC sections 3.1.1 to 3.3.7).
    def parse(value)
      unless value.is_a?(String)
        return AssertionResult.new(code: "bad_pointer", message: "The ABIZ TXT value must be a string.")
      end

      value = value.dup.force_encoding(Encoding::UTF_8) unless value.encoding == Encoding::UTF_8
      return AssertionResult.new(code: "bad_pointer", message: "The ABIZ TXT value is not valid UTF-8.") unless value.valid_encoding?

      tags, problem = tag_list(value)
      return AssertionResult.new(code: "bad_pointer", message: problem) if problem

      seen = {}
      unknown = {}
      tags.each do |name, val|
        if RECOGNISED.include?(name)
          return AssertionResult.new(code: "duplicate_tag", message: "The tag #{name}= appears more than once.") if seen.key?(name)

          seen[name] = val
        elsif !unknown.key?(name)
          unknown[name] = val
        end
      end
      raw_h = seen["h"]
      if raw_h.nil? || raw_h.empty?
        return AssertionResult.new(code: "missing_h", message: "The ABIZ TXT value has no h= tag naming the record host.")
      end

      h = Host.identity_parts(raw_h)
      if h.nil?
        return AssertionResult.new(code: "bad_pointer",
                                   message: "h= must be a host name with an optional path: no scheme, port, user name, query, fragment or \".\" segments.")
      end
      if Host.non_public_host?(Host.identity_hostname(h))
        return AssertionResult.new(code: "unsafe_host", message: "h= names a special-use or private-network host.")
      end

      k = seen["k"]
      unless k.nil?
        _key, key_problem = BusinessKey.parse(k)
        return AssertionResult.new(code: "bad_pointer", message: "k= is not an ABIZ 1.1 business key: #{key_problem}") if key_problem
      end
      p = seen["p"]
      if p.nil?
        return AssertionResult.new(code: "invalid_key",
                                   message: "The ABIZ TXT value has no p= tag. p is required (SPEC section 3.3.1): publish p= with the business's Ed25519 public key, 44 characters of standard base64 ending in one \"=\".")
      end
      unless public_key?(p)
        return AssertionResult.new(code: "invalid_key",
                                   message: "p= must be an Ed25519 public key: 44 characters of standard base64 (A-Z a-z 0-9 + /) ending in one \"=\", decoding to 32 bytes (SPEC section 3.3.2). Hex strings and base64url values are not accepted.")
      end

      AssertionResult.new(assertion: Assertion.new(h: h, k: k, p: p, unknown: unknown))
    end

    def clip(value)
      value.length > 40 ? "#{value[0, 40]}…" : value
    end
    private_class_method :clip

    # The assertion text carried by a well-known file's JSON object (SPEC section 3.4.2), as the
    # reference resolver builds it. Returns [text, nil] or [nil, message]; the text is then parsed
    # exactly as a DNS assertion.
    def text_from_well_known(document)
      return [nil, "The well-known file must be a JSON object."] unless document.is_a?(Hash)

      %w[v k h p].each do |member|
        return [nil, "Well-known member #{member} must be a string."] if document.key?(member) && !document[member].is_a?(String)
      end
      return [nil, "The well-known file must have \"v\": \"abiz1\"."] unless document["v"] == "abiz1"

      %w[h p].each do |member|
        return [nil, "The well-known file is missing #{member}."] unless document[member].is_a?(String)
      end
      parts = ["v=abiz1"]
      %w[k h p].each do |member|
        next unless document.key?(member)

        value = document[member]
        if value.empty? || value.match?(Regexp.new("[#{JS_SPACE};]"))
          return [nil, "Well-known member #{member} must be a non-empty value without whitespace or ';'."]
        end

        parts << "#{member}=#{value}"
      end
      [parts.join(";"), nil]
    end
  end
end
