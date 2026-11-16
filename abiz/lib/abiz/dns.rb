# frozen_string_literal: true

require "resolv"
require "socket"
require "io/wait"
require "securerandom"
require "json"
require "net/http"
require "uri"
require_relative "ports"
require_relative "version"

module Abiz
  # DNS adapters. Each answers query_txt(name) with a TxtLookup, and addresses(host) with
  # [:ok, [address, ...]] or [:error, reason] for the fetch guard.
  #
  # Ruby's Resolv::DNS#getresources returns an empty list for NXDOMAIN, NODATA, SERVFAIL, REFUSED
  # and a timeout alike (Resolv::DNS::Config#resolv rescues them), and applies the search list to
  # relative names. ABIZ must not treat a failure as absence, so Stub sends its own queries with
  # Resolv::DNS::Message (stdlib) and reads the response code itself.
  module Dns
    TIMEOUT = 2.5
    TYPE_A = Resolv::DNS::Resource::IN::A
    TYPE_AAAA = Resolv::DNS::Resource::IN::AAAA
    TYPE_TXT = Resolv::DNS::Resource::IN::TXT

    # A stub resolver over UDP (TCP when the answer is truncated) to the system's recursive
    # resolvers (/etc/resolv.conf) or the ones given. It trusts those resolvers' answers; it does
    # not validate DNSSEC. Names are always queried as absolute names (no search list).
    class Stub
      attr_reader :nameservers

      # nameservers:: ["1.1.1.1", ["192.0.2.53", 5353], ...]; default: the system's.
      # timeout::     seconds for the whole lookup (default 2.5).
      def initialize(nameservers: nil, timeout: TIMEOUT)
        @nameservers = (nameservers || system_nameservers).map { |ns| ns.is_a?(Array) ? ns : [ns, 53] }
        @timeout = timeout
      end

      def query_txt(name)
        reply = query(name, TYPE_TXT)
        return TxtLookup.error(reply) if reply.is_a?(Symbol)

        case reply.rcode
        when Resolv::DNS::RCode::NoError
          txt = reply.answer.select { |_n, _ttl, data| data.is_a?(TYPE_TXT) }
          if txt.empty?
            TxtLookup.nodata(ttl: authority_ttl(reply))
          else
            # Resolv::DNS joins a record's character-strings with nothing between them (#data).
            values = txt.map { |_n, _ttl, data| data.strings.join.dup.force_encoding(Encoding::UTF_8).scrub("\uFFFD") }
            TxtLookup.answer(values, ttl: txt.map { |_n, ttl, _d| ttl }.min)
          end
        when Resolv::DNS::RCode::NXDomain then TxtLookup.nxdomain(ttl: authority_ttl(reply))
        when Resolv::DNS::RCode::ServFail then TxtLookup.error(:servfail)
        when Resolv::DNS::RCode::Refused then TxtLookup.error(:refused)
        else TxtLookup.error(:malformed)
        end
      end

      # The A and AAAA addresses of +host+: [:ok, addresses] (NXDOMAIN and NODATA give an empty
      # list) or [:error, reason].
      def addresses(host)
        out = []
        [TYPE_A, TYPE_AAAA].each do |type|
          reply = query(host, type)
          return [:error, reply] if reply.is_a?(Symbol)

          rcode = reply.rcode
          next if rcode == Resolv::DNS::RCode::NXDomain
          return [:error, :servfail] unless rcode == Resolv::DNS::RCode::NoError

          reply.answer.each do |_n, _ttl, data|
            out << data.address.to_s.downcase if data.is_a?(type)
          end
        end
        [:ok, out]
      end

      private

      def system_nameservers
        config = Resolv::DNS::Config.default_config_hash
        list = Array(config[:nameserver])
        list = ["127.0.0.1"] if list.empty?
        list
      end

      def authority_ttl(reply)
        ttls = reply.authority.map { |_n, ttl, _d| ttl }
        ttls.empty? ? nil : ttls.min
      end

      # The decoded reply, or :timeout, :network or :malformed.
      def query(name, type)
        deadline = monotonic + @timeout
        absolute = Resolv::DNS::Name.create(name.end_with?(".") ? name : "#{name}.")
        last = :network
        @nameservers.each do |host, port|
          remaining = deadline - monotonic
          return :timeout if remaining <= 0

          reply = exchange_udp(absolute, type, host, port, remaining)
          if reply.is_a?(Resolv::DNS::Message) && reply.tc == 1
            remaining = deadline - monotonic
            return :timeout if remaining <= 0

            reply = exchange_tcp(absolute, type, host, port, remaining)
          end
          return reply if reply.is_a?(Resolv::DNS::Message)

          last = reply
        end
        last
      end

      def message(name, type)
        msg = Resolv::DNS::Message.new(SecureRandom.random_number(0x10000))
        msg.rd = 1
        msg.add_question(name, type)
        msg
      end

      def check(reply, query)
        return :malformed unless reply.id == query.id && reply.qr == 1

        q = reply.question.first
        return :malformed unless q && q[0] == query.question.first[0] && q[1] == query.question.first[1]

        reply
      end

      def exchange_udp(name, type, host, port, timeout)
        query = message(name, type)
        family = host.include?(":") ? Socket::AF_INET6 : Socket::AF_INET
        socket = UDPSocket.new(family)
        begin
          socket.connect(host, port)
          socket.send(query.encode, 0)
          deadline = monotonic + timeout
          loop do
            remaining = deadline - monotonic
            return :timeout if remaining <= 0
            return :timeout unless socket.wait_readable(remaining)

            data = socket.recv(65_535)
            begin
              reply = Resolv::DNS::Message.decode(data)
            rescue Resolv::DNS::DecodeError, StandardError
              return :malformed
            end
            # Ignore a datagram that does not answer this query (spoofing or a late reply).
            next unless reply.id == query.id

            return check(reply, query)
          end
        rescue SystemCallError, IOError, SocketError
          :network
        ensure
          socket&.close
        end
      end

      def exchange_tcp(name, type, host, port, timeout)
        query = message(name, type)
        deadline = monotonic + timeout
        socket = Socket.tcp(host, port, connect_timeout: timeout)
        begin
          payload = query.encode
          socket.write([payload.bytesize].pack("n") + payload)
          head = read_exactly(socket, 2, deadline)
          return head if head.is_a?(Symbol)

          body = read_exactly(socket, head.unpack1("n"), deadline)
          return body if body.is_a?(Symbol)

          begin
            check(Resolv::DNS::Message.decode(body), query)
          rescue Resolv::DNS::DecodeError, StandardError
            :malformed
          end
        ensure
          socket.close
        end
      rescue Errno::ETIMEDOUT
        :timeout
      rescue SystemCallError, IOError, SocketError
        :network
      end

      def read_exactly(socket, size, deadline)
        out = +""
        while out.bytesize < size
          remaining = deadline - monotonic
          return :timeout if remaining <= 0
          return :timeout unless socket.wait_readable(remaining)

          chunk = socket.read_nonblock(size - out.bytesize, exception: false)
          next if chunk == :wait_readable
          return :network if chunk.nil?

          out << chunk
        end
        out
      end

      def monotonic
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end

    # DNS-over-HTTPS with the JSON API (application/dns-json), as the hosted resolver uses. It
    # trusts the upstream's answer (the upstream may validate DNSSEC; this adapter does not). Useful
    # where outbound UDP port 53 is blocked. The upstream is a fixed, trusted URL, so it is
    # fetched directly, not through the record fetch guard.
    class DoH
      UPSTREAMS = {
        cloudflare: "https://cloudflare-dns.com/dns-query",
        google: "https://dns.google/resolve"
      }.freeze
      MAX_BYTES = 65_536

      def initialize(url: UPSTREAMS[:cloudflare], timeout: TIMEOUT)
        @uri = URI(url)
        raise ArgumentError, "a DoH upstream must be https" unless @uri.scheme == "https"

        @timeout = timeout
      end

      def query_txt(name)
        json = get(name, "TXT")
        return TxtLookup.error(json) if json.is_a?(Symbol)

        case json["Status"]
        when 0
          rows = records(json["Answer"]).select { |r| r[:type] == 16 }
          return TxtLookup.nodata(ttl: min_ttl(records(json["Authority"]))) if rows.empty?

          TxtLookup.answer(rows.map { |r| Dns.decode_txt_data(r[:data]) }, ttl: min_ttl(rows))
        when 3 then TxtLookup.nxdomain(ttl: min_ttl(records(json["Authority"])))
        when 2 then TxtLookup.error(:servfail)
        when 5 then TxtLookup.error(:refused)
        else TxtLookup.error(:malformed)
        end
      end

      def addresses(host)
        out = []
        [["A", 1], ["AAAA", 28]].each do |type, number|
          json = get(host, type)
          return [:error, json] if json.is_a?(Symbol)
          return [:error, :servfail] unless [0, 3].include?(json["Status"])

          records(json["Answer"]).each { |r| out << r[:data].downcase if r[:type] == number }
        end
        [:ok, out]
      end

      private

      def records(section)
        return [] unless section.is_a?(Array)

        section.filter_map do |row|
          next unless row.is_a?(Hash) && row["type"].is_a?(Integer) && row["data"].is_a?(String)

          { type: row["type"], data: row["data"], ttl: row["TTL"].is_a?(Integer) ? row["TTL"] : nil }
        end
      end

      def min_ttl(rows)
        ttls = rows.map { |r| r[:ttl] }.compact
        ttls.empty? ? nil : ttls.min
      end

      def get(name, type)
        uri = @uri.dup
        uri.query = URI.encode_www_form(name: name, type: type)
        http = Net::HTTP.new(uri.host, uri.port, nil)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.open_timeout = @timeout
        http.read_timeout = @timeout
        http.ssl_timeout = @timeout
        http.write_timeout = @timeout
        request = Net::HTTP::Get.new(uri)
        request["Accept"] = "application/dns-json"
        request["User-Agent"] = Abiz::USER_AGENT
        body = nil
        status = nil
        http.start do
          http.request(request) do |response|
            status = response.code.to_i
            body = +""
            response.read_body do |chunk|
              body << chunk
              raise IOError, "DoH answer too large" if body.bytesize > MAX_BYTES
            end
          end
        end
        return :network unless status == 200

        json = JSON.parse(body.force_encoding(Encoding::UTF_8))
        json.is_a?(Hash) && json["Status"].is_a?(Integer) ? json : :malformed
      rescue JSON::ParserError
        :malformed
      rescue Net::OpenTimeout, Net::ReadTimeout, Net::WriteTimeout, Timeout::Error
        :timeout
      rescue OpenSSL::SSL::SSLError, SystemCallError, IOError, SocketError, Net::HTTPBadResponse, Net::ProtocolError
        :network
      end
    end

    # One TXT record's value from a DoH JSON answer: quoted character-strings ("one" "two") are
    # joined with nothing between them, with \", \\ and \DDD decoded; an unquoted value is kept.
    def self.decode_txt_data(data)
      text = data.strip
      return text unless text.start_with?("\"")

      out = +"".b
      bytes = text.b
      i = 0
      while i < bytes.bytesize
        i += 1 while i < bytes.bytesize && bytes.getbyte(i) == 0x20
        break if i >= bytes.bytesize

        unless bytes.getbyte(i) == 0x22
          out << bytes.byteslice(i, bytes.bytesize - i)
          break
        end
        i += 1
        while i < bytes.bytesize && bytes.getbyte(i) != 0x22
          ch = bytes.getbyte(i)
          if ch == 0x5c && i + 1 < bytes.bytesize
            digits = bytes.byteslice(i + 1, 3)
            if digits.match?(/\A[0-9]{3}\z/n)
              code = digits.to_i
              out << (code <= 255 ? code.chr : "?")
              i += 4
              next
            end
            out << bytes.byteslice(i + 1, 1)
            i += 2
            next
          end
          out << ch.chr
          i += 1
        end
        i += 1
      end
      out.force_encoding(Encoding::UTF_8).scrub("\uFFFD")
    end
  end
end
