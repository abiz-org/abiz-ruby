# frozen_string_literal: true

module Abiz
  # The outcome of one TXT query. Absence (+:nxdomain+, +:nodata+) and failure (+:error+) stay
  # different things.
  #
  # kind::   :answer, :nxdomain, :nodata or :error
  # values:: for :answer, each TXT record's character-strings joined with nothing between them
  # ttl::    seconds, or nil
  # reason:: for :error, :timeout, :network, :servfail, :refused or :malformed
  TxtLookup = Struct.new(:kind, :values, :ttl, :reason, keyword_init: true) do
    def self.answer(values, ttl: nil) = new(kind: :answer, values: values, ttl: ttl)
    def self.nxdomain(ttl: nil) = new(kind: :nxdomain, values: [], ttl: ttl)
    def self.nodata(ttl: nil) = new(kind: :nodata, values: [], ttl: ttl)
    def self.error(reason) = new(kind: :error, values: [], reason: reason)
  end

  # The outcome of one guarded HTTPS GET.
  #
  # kind::         :response, :blocked (the SSRF guard refused it), :no_address (no A or AAAA),
  #                :dns_error (the address lookup failed), :timeout or :network
  # status::       the HTTP status, for :response
  # content_type:: the Content-Type header, or nil
  # body::         the body as a UTF-8 String, or nil when it was larger than 64 KiB
  # message::      for :blocked, why
  FetchOutcome = Struct.new(:kind, :status, :content_type, :body, :message, keyword_init: true) do
    def self.response(status, content_type, body) = new(kind: :response, status: status, content_type: content_type, body: body)
    def self.blocked(message = "The address is not a public web origin.") = new(kind: :blocked, message: message)
    def self.no_address = new(kind: :no_address)
    def self.dns_error = new(kind: :dns_error)
    def self.timeout = new(kind: :timeout)
    def self.network = new(kind: :network)
  end

  # A DNS adapter answers +query_txt(name)+ with a TxtLookup. An HTTP adapter answers
  # +fetch(url)+ with a FetchOutcome and is responsible for the fetch guard (SPEC section 9).
  # Abiz::Dns::Stub, Abiz::Dns::DoH and Abiz::Http::GuardedFetcher are the bundled ones; any object
  # with the same method works (a cache, a proxy, a test double).
end
