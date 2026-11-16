# frozen_string_literal: true

require "json"
require "set"

module Abiz
  # The ABIZ 1.1 business key (SPEC section 4.2): country "-" [subdivision "-"] reg-number, used as
  # the DNS k tag and the record's business_key.
  module BusinessKey
    # A parsed key. +canonical+: lower-case country and subdivision, upper-case number.
    Parsed = Struct.new(:country, :subdivision, :number, :canonical, keyword_init: true)

    MAX_LENGTH = 128
    # SPEC section 4.2.7: assigned, but ABIZ does not support a business there.
    UNSUPPORTED_COUNTRIES = Set["kp"].freeze
    # SPEC section 4.2.2. :provincial means required except for a federal (Corporations Canada) key.
    SUBDIVISION_RULE = { "us" => :required, "ae" => :required, "ca" => :provincial }.freeze
    REG_NUMBER = /\A[A-Za-z0-9]+\z/

    ISO3166_PATH = File.expand_path("data/iso3166.json", __dir__)

    module_function

    def iso3166
      @iso3166 ||= begin
        data = JSON.parse(File.read(ISO3166_PATH, mode: "rb").force_encoding(Encoding::UTF_8))
        {
          countries: Set.new(data.fetch("countries")).freeze,
          subdivisions: data.fetch("subdivisions").transform_values { |codes| Set.new(codes).freeze }.freeze
        }.freeze
      end
    end

    # True when +code+ is an assigned ISO 3166-1 alpha-2 code, in any case (kp included).
    def assigned_country?(code)
      code.is_a?(String) && code.match?(/\A[A-Za-z]{2}\z/) && iso3166[:countries].include?(code.downcase)
    end

    # A message when the country is assigned but unsupported (kp), else nil.
    def country_support_problem(code)
      return nil unless UNSUPPORTED_COUNTRIES.include?(code.downcase)

      "\"#{code}\" is not supported by ABIZ (SPEC section 4.2.7)."
    end

    # An ISO 3166-2 region code against its country (SPEC section 4.7.13). Subdivisions are
    # confirmed only for us, ca and ae; other countries are checked for the country part.
    def region_code_problem(code, country)
      dash = code.index("-")
      prefix = dash.nil? ? code : code[0...dash]
      sub = dash.nil? ? "" : code[(dash + 1)..]
      return "region code \"#{code}\" does not belong to country \"#{country}\"." if prefix.downcase != country.downcase

      known = iso3166[:subdivisions][country.downcase]
      return "region code \"#{code}\" is not an assigned ISO 3166-2 code." if known && !known.include?(sub.downcase)

      nil
    end

    # Parse a business key. Returns [Parsed, nil] or [nil, message].
    def parse(value)
      return [nil, "A business key must be a string."] unless value.is_a?(String)
      return [nil, "A business key is at most #{MAX_LENGTH} characters."] if value.length > MAX_LENGTH

      parts = value.split("-", -1)
      unless [2, 3].include?(parts.length)
        return [nil, "A business key is country-number or country-subdivision-number, for example gb-01234567 or us-or-123456."]
      end

      raw_country, raw_sub, raw_number = parts.length == 2 ? [parts[0], nil, parts[1]] : parts
      unless assigned_country?(raw_country)
        return [nil, "\"#{raw_country[0, 8]}\" is not an assigned ISO 3166-1 alpha-2 country code (the United Kingdom is gb)."]
      end
      unsupported = country_support_problem(raw_country)
      return [nil, unsupported] if unsupported

      country = raw_country.downcase
      return [nil, "The registration number in a business key must be ASCII letters and digits only."] unless raw_number.match?(REG_NUMBER)

      rule = SUBDIVISION_RULE[country]
      subdivision = nil
      if raw_sub.nil?
        if rule == :required
          example = country == "us" ? "us-or-123456" : "ae-du-1234567"
          return [nil, "A business key for #{country} must include the subdivision, for example #{example}."]
        end
      else
        return [nil, "A business key subdivision is 1 to 3 ASCII letters or digits."] unless raw_sub.match?(/\A[A-Za-z0-9]{1,3}\z/)
        return [nil, "A business key for #{country} must not include a subdivision."] unless rule

        subdivision = raw_sub.downcase
        unless iso3166[:subdivisions][country]&.include?(subdivision)
          return [nil, "#{country}-#{subdivision} is not a permitted ISO 3166-2 subdivision for a business key."]
        end
      end
      number = raw_number.upcase
      canonical = [country, subdivision, number].compact.join("-")
      [Parsed.new(country: country, subdivision: subdivision, number: number, canonical: canonical), nil]
    end

    # Two business keys are the same key when they match ignoring ASCII case (SPEC section 4.2.4).
    def same?(a, b)
      a.downcase == b.downcase
    end
  end
end
