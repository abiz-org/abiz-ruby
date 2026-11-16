# frozen_string_literal: true

module Abiz
  # Which resolved addresses a fetch may connect to (SPEC section 9; the reference resolver's
  # address.ts): public unicast IPv4 outside every special-purpose block in the IANA registry, and
  # IPv6 global unicast (2000::/3) outside the documentation, 6to4 and Teredo ranges, whose
  # embedded IPv4 could be private. IPv4-mapped and NAT64 addresses are refused.
  module Address
    V4 = /\A(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\z/

    V4_SPECIAL = [
      [[0, 0, 0, 0], 8], [[10, 0, 0, 0], 8], [[100, 64, 0, 0], 10], [[127, 0, 0, 0], 8],
      [[169, 254, 0, 0], 16], [[172, 16, 0, 0], 12], [[192, 0, 0, 0], 24], [[192, 0, 2, 0], 24],
      [[192, 31, 196, 0], 24], [[192, 52, 193, 0], 24], [[192, 88, 99, 0], 24], [[192, 168, 0, 0], 16],
      [[192, 175, 48, 0], 24], [[198, 18, 0, 0], 15], [[198, 51, 100, 0], 24], [[203, 0, 113, 0], 24],
      [[224, 0, 0, 0], 4], [[240, 0, 0, 0], 4]
    ].map { |(o, len)| [(o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3], len] }.freeze

    BLOCKED_HOSTNAMES = %w[localhost localhost.localdomain ip6-localhost ip6-loopback].freeze
    BLOCKED_SUFFIXES = %w[.internal .local .localhost .intranet .lan .corp .home .test].freeze

    module_function

    def parse_v4(text)
      m = V4.match(text)
      return nil unless m

      octets = m.captures.map(&:to_i)
      return nil if octets.any? { |n| n > 255 }

      (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    end

    def v4_public?(n)
      V4_SPECIAL.none? do |net, len|
        mask = len.zero? ? 0 : (0xffffffff << (32 - len)) & 0xffffffff
        (n & mask) == net
      end
    end
    private_class_method :v4_public?

    # The eight 16-bit groups of an IPv6 address (a dotted IPv4 tail allowed), or nil.
    def ipv6_groups(text)
      t = text.downcase.sub(/\A\[/, "").sub(/\]\z/, "").sub(/%.*\z/m, "")
      if (tail = /\A(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\z/.match(t))
        n = parse_v4(tail[2])
        return nil if n.nil?

        t = "#{tail[1]}#{(n >> 16).to_s(16)}:#{(n & 0xffff).to_s(16)}"
      end
      halves = t.split("::", -1)
      return nil if halves.length > 2

      part = ->(s) { s.empty? ? [] : s.split(":", -1) }
      head = part.call(halves[0])
      rest = halves.length == 2 ? part.call(halves[1]) : []
      fill = 8 - head.length - rest.length
      return nil if halves.length == 2 ? fill < 1 : fill != 0

      groups = head + (["0"] * (halves.length == 2 ? fill : 0)) + rest
      return nil unless groups.all? { |g| g.match?(/\A[0-9a-f]{1,4}\z/) }

      groups.map { |g| g.to_i(16) }
    end

    # A coarse, name-level refusal (the reference's isBlockedAddress): local names, private
    # suffixes, and private or loopback IP literals in any IPv4 spelling.
    def blocked_name?(hostname)
      host = hostname.to_s.strip.downcase.sub(/\.\z/, "")
      return true if host.empty?
      return blocked_v6?(host[1...-1]) if host.start_with?("[") && host.end_with?("]")
      return true if BLOCKED_HOSTNAMES.include?(host)
      return true if BLOCKED_SUFFIXES.any? { |suffix| host.end_with?(suffix) }

      v4 = obfuscated_v4(host)
      return blocked_v4?(v4) if v4
      return blocked_v6?(host) if host.include?(":")

      false
    end

    def int_token(token)
      return nil if token.empty?
      return token[2..].to_i(16) if token.match?(/\A0x[0-9a-f]+\z/i)
      return token[1..].to_i(8) if token.match?(/\A0[0-7]+\z/)
      return token.to_i if token.match?(/\A\d+\z/)

      nil
    end
    private_class_method :int_token

    def obfuscated_v4(host)
      parts = host.split(".", -1)
      if parts.length == 1
        n = int_token(host)
        return nil if n.nil? || n.negative? || n > 0xffffffff

        return [(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]
      end
      return nil unless parts.length == 4

      octets = parts.map { |p| int_token(p) }
      return nil if octets.any? { |n| n.nil? || n.negative? || n > 0xff }

      octets
    end
    private_class_method :obfuscated_v4

    def blocked_v4?(octets)
      a, b = octets
      a.zero? || a == 127 || a == 10 || (a == 172 && b.between?(16, 31)) || (a == 192 && b == 168) ||
        (a == 169 && b == 254) || (a == 100 && b.between?(64, 127)) || a >= 224
    end
    private_class_method :blocked_v4?

    def blocked_v6?(addr)
      ip = addr.sub(/%.*\z/m, "")
      return true if ip == "::1" || ip == "::"

      if (mapped = /\A::(?:ffff:)?(\d+\.\d+\.\d+\.\d+)\z/.match(ip))
        v4 = obfuscated_v4(mapped[1])
        return v4 ? blocked_v4?(v4) : true
      end
      head = ip.split(":", 2).first.to_s
      return false unless head.empty? || head.match?(/\A[0-9a-f]+\z/i)

      first = head.empty? ? 0 : head.to_i(16)
      return true if (first & 0xfe00) == 0xfc00
      return true if (first & 0xffc0) == 0xfe80
      return true if (first & 0xff00) == 0xff00

      false
    end
    private_class_method :blocked_v6?

    # True only for an address a fetch may connect to.
    def public?(address)
      return false unless address.is_a?(String)
      return false if blocked_name?(address)

      v4 = parse_v4(address)
      return v4_public?(v4) unless v4.nil?

      g = ipv6_groups(address)
      return false if g.nil?

      first = g[0]
      return false if (first & 0xe000) != 0x2000
      return false if first == 0x2001 && g[1] == 0x0db8
      return false if first == 0x2001 && g[1] < 0x0200
      return false if first == 0x2002
      return false if first == 0x3fff && g[1] < 0x1000

      true
    end
  end
end
