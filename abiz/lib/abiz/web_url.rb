# frozen_string_literal: true

require "ipaddr"
require "simpleidn"

module Abiz
  # The parts of the WHATWG URL Standard the ABIZ checks depend on, for http and https URLs:
  # scheme, credentials, host (IDNA to A-labels, IPv4 in any of its numeric spellings), port
  # (the default port reads as none) and whether a fragment is present. The reference resolver and
  # validator use a WHATWG parser; Ruby's URI follows RFC 3986 and differs on exactly these points.
  module WebUrl
    # A parsed URL. +hostname+ is lower case and in A-labels; an IPv6 host keeps its brackets.
    Parsed = Struct.new(:scheme, :username, :password, :hostname, :port, :fragment, :path_and_query, keyword_init: true)

    SPECIAL_PORTS = { "http" => 80, "https" => 443 }.freeze
    # Forbidden domain code points (WHATWG URL section 3.2), C0 controls and DEL included.
    FORBIDDEN_DOMAIN = /[\u0000- #%\/:<>?@\[\\\]^|\u007f]/

    module_function

    # Parse an absolute http or https URL. Returns nil when the URL Standard's parser would fail.
    # For any other scheme the result carries only +scheme+.
    def parse(input)
      return nil unless input.is_a?(String)

      s = input.dup.force_encoding(Encoding::UTF_8)
      return nil unless s.valid_encoding?

      s = s.sub(/\A[\u0000- ]+/, "").sub(/[\u0000- ]+\z/, "").delete("\t\n\r")
      m = /\A([A-Za-z][A-Za-z0-9+\-.]*):/.match(s)
      return nil unless m

      scheme = m[1].downcase
      return Parsed.new(scheme: scheme) unless SPECIAL_PORTS.key?(scheme)

      rest = m.post_match.sub(%r{\A[/\\]*}, "")
      cut = rest.index(%r{[/\\?#]}) || rest.length
      authority = rest[0...cut]
      after = rest[cut..] || ""
      fragment = nil
      if (hash = after.index("#"))
        fragment = after[(hash + 1)..]
        after = after[0...hash]
      end
      username = ""
      password = ""
      if (at = authority.rindex("@"))
        userinfo = authority[0...at]
        authority = authority[(at + 1)..]
        username, password = userinfo.split(":", 2)
        username ||= ""
        password ||= ""
      end
      host_text, port_text = split_host_port(authority)
      return nil if host_text.nil?

      port = nil
      unless port_text.nil? || port_text.empty?
        return nil unless port_text.match?(/\A[0-9]+\z/)

        port = port_text.to_i
        return nil if port > 65_535

        port = nil if port == SPECIAL_PORTS[scheme]
      end
      hostname = parse_host(host_text)
      return nil if hostname.nil?

      Parsed.new(scheme: scheme, username: username, password: password, hostname: hostname, port: port,
                 fragment: fragment, path_and_query: after)
    end

    def split_host_port(authority)
      if authority.start_with?("[")
        close = authority.index("]")
        return nil if close.nil?

        host = authority[0..close]
        tail = authority[(close + 1)..]
        return [host, nil] if tail.empty?
        return nil unless tail.start_with?(":")

        [host, tail[1..]]
      else
        host, port = authority.split(":", 2)
        [host || "", port]
      end
    end
    private_class_method :split_host_port

    # The URL Standard's host parser for a special scheme: "" fails, "[...]" is IPv6, otherwise
    # percent-decoded, mapped to A-labels (UTS #46) and checked; a name ending in a number is IPv4.
    def parse_host(text)
      return nil if text.empty?

      if text.start_with?("[")
        return nil unless text.end_with?("]")

        begin
          addr = IPAddr.new(text[1...-1])
        rescue IPAddr::Error, ArgumentError
          return nil
        end
        return nil unless addr.ipv6?

        return "[#{addr}]"
      end
      decoded = text.b.gsub(/%([0-9A-Fa-f]{2})/n) { Regexp.last_match(1).hex.chr }.force_encoding(Encoding::UTF_8)
      return nil unless decoded.valid_encoding?

      ascii = domain_to_ascii(decoded)
      return nil if ascii.nil? || ascii.empty? || ascii.match?(FORBIDDEN_DOMAIN)

      if ends_in_number?(ascii)
        ipv4 = parse_ipv4(ascii)
        return ipv4
      end
      ascii
    end

    # UTS #46 ToASCII as the URL Standard calls it (not strict): ASCII is lower-cased, anything
    # else mapped and Punycode-encoded per label.
    def domain_to_ascii(text)
      return text.downcase if text.ascii_only?

      SimpleIDN.to_ascii(text)&.downcase
    rescue StandardError
      nil
    end

    def ends_in_number?(host)
      labels = host.split(".", -1)
      if labels.last == ""
        return false if labels.length == 1

        labels.pop
      end
      last = labels.last.to_s
      return true if !last.empty? && last.match?(/\A[0-9]+\z/)

      !parse_ipv4_number(last).nil?
    end
    private_class_method :ends_in_number?

    def parse_ipv4_number(part)
      return nil if part.empty?

      if part.match?(/\A0[xX][0-9A-Fa-f]*\z/)
        hex = part[2..]
        return hex.empty? ? 0 : hex.to_i(16)
      end
      return part[1..].to_i(8) if part.match?(/\A0[0-7]+\z/)
      return part.to_i(10) if part.match?(/\A[0-9]+\z/)

      nil
    end
    private_class_method :parse_ipv4_number

    # The URL Standard's IPv4 parser; nil on failure, else the dotted-decimal form.
    def parse_ipv4(host)
      parts = host.split(".", -1)
      parts.pop if parts.last == "" && parts.length > 1
      return nil if parts.length > 4 || parts.empty?

      numbers = parts.map { |part| parse_ipv4_number(part) }
      return nil if numbers.any?(&:nil?)
      return nil if numbers[0...-1].any? { |n| n > 255 }
      return nil if numbers.last >= 256**(5 - numbers.length)

      ipv4 = numbers.last
      numbers[0...-1].each_with_index { |n, i| ipv4 += n * (256**(3 - i)) }
      [24, 16, 8, 0].map { |shift| (ipv4 >> shift) & 0xff }.join(".")
    end
    private_class_method :parse_ipv4
  end
end
