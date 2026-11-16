# frozen_string_literal: true

module Abiz
  # RFC 8785 JSON Canonicalization Scheme: no whitespace, object members sorted by the UTF-16 code
  # units of their names, strings escaped as RFC 8785 section 3.2.2.2 asks, and every number
  # written as ECMAScript writes an IEEE 754 double (section 3.2.2.3; -0 is written 0).
  module JCS
    # Raised for a value RFC 8785 cannot canonicalise (not I-JSON).
    class Error < StandardError; end

    module_function

    # The canonical text of +value+ (Hash with String keys, Array, String, Integer, Float, true,
    # false, nil). Integers are converted to doubles first, as ECMAScript reads JSON numbers.
    def canonicalize(value)
      out = +""
      write(value, out)
      out.force_encoding(Encoding::UTF_8)
    end

    def write(value, out)
      case value
      when nil then out << "null"
      when true then out << "true"
      when false then out << "false"
      when String then out << string(value)
      when Integer, Float then out << number(value)
      when Array
        out << "["
        value.each_with_index do |item, index|
          out << "," if index.positive?
          write(item, out)
        end
        out << "]"
      when Hash
        entries = value.map do |key, item|
          raise Error, "object member names must be strings" unless key.is_a?(String)

          [key, item]
        end
        entries.sort_by! { |key, _| utf16_key(key) }
        out << "{"
        entries.each_with_index do |(key, item), index|
          out << "," if index.positive?
          out << string(key) << ":"
          write(item, out)
        end
        out << "}"
      else
        raise Error, "a #{value.class} is not a JSON value"
      end
    end
    private_class_method :write

    def utf16_key(key)
      check_string(key)
      key.encode(Encoding::UTF_16BE).b
    end
    private_class_method :utf16_key

    ESCAPES = { "\"" => "\\\"", "\\" => "\\\\", "\b" => "\\b", "\t" => "\\t", "\n" => "\\n", "\f" => "\\f", "\r" => "\\r" }.freeze

    def check_string(value)
      str = value.encoding == Encoding::UTF_8 ? value : value.dup.force_encoding(Encoding::UTF_8)
      raise Error, "a string is not valid UTF-8 (or holds a lone surrogate)" unless str.valid_encoding?

      str
    end
    private_class_method :check_string

    def string(value)
      str = check_string(value)
      body = str.gsub(/["\\\x00-\x1f]/) do |ch|
        ESCAPES[ch] || format("\\u%04x", ch.ord)
      end
      "\"#{body}\""
    end
    private_class_method :string

    # ECMAScript Number::toString for a finite double (ECMA-262 section 6.1.6.1.20), using Ruby's
    # shortest round-trip digits (Float#to_s).
    def number(value)
      f = to_double(value)
      raise Error, "a number is NaN or infinite (not I-JSON)" if f.nan? || f.infinite?
      return "0" if f.zero?

      sign = f.negative? ? "-" : ""
      digits, n = decimal_parts(f.abs)
      k = digits.length
      body =
        if k <= n && n <= 21
          digits + ("0" * (n - k))
        elsif n.positive? && n <= 21
          "#{digits[0, n]}.#{digits[n..]}"
        elsif n > -6 && n <= 0
          "0.#{"0" * -n}#{digits}"
        else
          e = n - 1
          exp = e.negative? ? "-#{-e}" : "+#{e}"
          k == 1 ? "#{digits}e#{exp}" : "#{digits[0]}.#{digits[1..]}e#{exp}"
        end
      sign + body
    end
    private_class_method :number

    # The double nearest to +value+ (Infinity beyond range), without Ruby's range warning.
    def to_double(value)
      return value if value.is_a?(Float)

      verbose = $VERBOSE
      $VERBOSE = nil
      value.to_f
    ensure
      $VERBOSE = verbose
    end
    private_class_method :to_double

    # The shortest digit string s (no leading or trailing zeros) and exponent n with
    # value = 0.s * 10**n, from Float#to_s ("123.45", "1.0e+21", "5.0e-324").
    def decimal_parts(positive)
      text = positive.to_s
      mantissa, exponent = text.split("e", 2)
      exp = exponent ? Integer(exponent, 10) : 0
      int_part, frac_part = mantissa.split(".", 2)
      frac_part ||= ""
      all = int_part + frac_part
      point = int_part.length + exp
      stripped = all.sub(/\A0+/, "")
      point -= all.length - stripped.length
      stripped = stripped.sub(/0+\z/, "")
      [stripped, point]
    end
    private_class_method :decimal_parts
  end
end
