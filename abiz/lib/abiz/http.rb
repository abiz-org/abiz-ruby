# frozen_string_literal: true

require "net/http"
require "openssl"
require "timeout"
require "zlib"
require_relative "address"
require_relative "dns"
require_relative "ports"
require_relative "version"

module Abiz
  module Http
    FETCH_TIMEOUT = 5.0
    MAX_BYTES = 65_536

    # The fetch guard (SPEC section 9) around one HTTPS GET:
    #
    # - https only, on the default port, no credentials; a local or private name is refused;
    # - the host's A and AAAA records are looked up first and every address must be public
    #   (Abiz::Address.public?), else :blocked; none is :no_address, a failed lookup :dns_error;
    # - the connection goes to the checked address (Net::HTTP#ipaddr=), while the host name is kept
    #   for SNI, certificate verification and the Host header, so DNS is not consulted again
    #   (no rebinding window);
    # - the certificate is verified; no proxy is used (a proxy would make its own lookup);
    # - redirects are never followed; 5 seconds for the whole exchange; at most 64 KiB of body
    #   (counted after content decoding), else body nil;
    # - Accept: application/json and User-Agent abiz-ruby/<version>.
    class GuardedFetcher
      # resolver::   anything with addresses(host) -> [:ok, [...]] or [:error, reason]
      #              (Abiz::Dns::Stub by default).
      # cert_store:: an OpenSSL::X509::Store to verify certificates against; default: the
      #              system's trusted roots. Verification is never turned off.
      def initialize(resolver: Dns::Stub.new, timeout: FETCH_TIMEOUT, max_bytes: MAX_BYTES, user_agent: Abiz::USER_AGENT,
                     cert_store: nil)
        @resolver = resolver
        @cert_store = cert_store
        @port = 443
        @timeout = timeout
        @max_bytes = max_bytes
        @user_agent = user_agent
      end

      def fetch(url)
        target = parse(url)
        return FetchOutcome.blocked(target) if target.is_a?(String)

        host, request_target = target
        found = @resolver.addresses(host)
        return FetchOutcome.dns_error unless found[0] == :ok

        addresses = found[1].uniq
        return FetchOutcome.no_address if addresses.empty?
        unless addresses.all? { |a| Address.public?(a) }
          return FetchOutcome.blocked("The host resolves to a private, reserved or special-purpose address.")
        end

        get(host, preferred(addresses), request_target)
      end

      private

      # [host, request_target] or a refusal message.
      def parse(url)
        return "The address is not a valid URL." unless url.is_a?(String)

        m = %r{\Ahttps://([^/?#]+)([^#]*)\z}.match(url)
        return "Only https URLs are fetched." unless m

        authority = m[1]
        return "Only https on the default port is fetched, without credentials." if authority.include?("@") || authority.include?(":")

        host = authority.downcase
        return "The host is not a DNS host name." unless host.match?(/\A[a-z0-9.-]+\z/)
        return "The host is a private or special-use name." if Address.blocked_name?(host) || host.match?(/\A[0-9.]+\z/) || !host.include?(".")

        rest = m[2]
        rest = "/#{rest}" unless rest.start_with?("/")
        # Percent-encode what the URL Standard's path and query encode sets would.
        target = rest.gsub(/["<>`{} ]|[^\x21-\x7e]/) { |ch| ch.bytes.map { |b| format("%%%02X", b) }.join }
        [host.sub(/\.\z/, ""), target]
      end

      def preferred(addresses)
        addresses.find { |a| a.include?(".") } || addresses.first
      end

      def get(host, address, request_target)
        deadline = monotonic + @timeout
        http = Net::HTTP.new(host, @port, nil)
        http.ipaddr = address
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.cert_store = @cert_store if @cert_store
        http.verify_hostname = true if http.respond_to?(:verify_hostname=)
        http.open_timeout = @timeout
        http.ssl_timeout = @timeout
        http.read_timeout = @timeout
        http.write_timeout = @timeout
        http.keep_alive_timeout = 0
        http.max_retries = 0

        request = Net::HTTP::Get.new(request_target)
        request["Accept"] = "application/json"
        request["User-Agent"] = @user_agent

        outcome = nil
        begin
          Timeout.timeout(@timeout, Net::ReadTimeout) do
            http.start do
              http.request(request) do |response|
                status = response.code.to_i
                content_type = response["content-type"]
                # Stop here: the body of any other status is never read.
                raise Abort, FetchOutcome.response(status, content_type, "") if status != 200

                body = +"".b
                response.read_body do |chunk|
                  raise Net::ReadTimeout if monotonic > deadline

                  body << chunk
                  # Stop reading at the cap; the connection is closed, not drained.
                  raise Abort, FetchOutcome.response(200, content_type, nil) if body.bytesize > @max_bytes
                end
                outcome = FetchOutcome.response(200, content_type, decode(body))
              end
            end
          end
        rescue Abort => e
          outcome = e.outcome
        end
        outcome || FetchOutcome.network
      rescue Net::OpenTimeout, Net::ReadTimeout, Net::WriteTimeout, Timeout::Error
        FetchOutcome.timeout
      rescue OpenSSL::SSL::SSLError, SystemCallError, IOError, SocketError, EOFError,
             Net::HTTPBadResponse, Net::ProtocolError, Zlib::Error
        FetchOutcome.network
      end

      # Raised inside the response block to end the exchange early with a known outcome.
      class Abort < StandardError
        attr_reader :outcome

        def initialize(outcome)
          @outcome = outcome
          super("fetch ended early")
        end
      end
      private_constant :Abort

      # UTF-8, a leading byte order mark dropped and invalid sequences replaced, as a browser's
      # TextDecoder reads a body.
      def decode(bytes)
        text = bytes.force_encoding(Encoding::UTF_8)
        text = text.byteslice(3, text.bytesize - 3).force_encoding(Encoding::UTF_8) if text.start_with?("﻿")
        text.scrub("�")
      end

      def monotonic
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end
  end
end
