# frozen_string_literal: true

require_relative "test_helper"
require "openssl"
require "socket"

# The fetch guard: refusals before any connection, against a stubbed resolver, and the real HTTPS
# path against a local TLS server (the connection pinned to the checked address, SNI and the Host
# header kept as the name, the certificate verified, no redirect followed, the 64 KiB cap).
class FetchGuardTest < Minitest::Test
  class StubResolver
    attr_reader :asked

    def initialize(answer)
      @answer = answer
      @asked = []
    end

    def addresses(host)
      @asked << host
      @answer
    end
  end

  def fetcher(answer)
    resolver = StubResolver.new(answer)
    [Abiz::Http::GuardedFetcher.new(resolver: resolver), resolver]
  end

  def test_refuses_a_private_address
    f, = fetcher([:ok, ["10.0.0.7"]])
    out = f.fetch("https://records.example.org/acme?format=json")
    assert_equal :blocked, out.kind
  end

  def test_refuses_when_any_address_is_private
    f, = fetcher([:ok, ["93.184.215.14", "127.0.0.1"]])
    assert_equal :blocked, f.fetch("https://records.example.org/?format=json").kind
    f, = fetcher([:ok, ["2606:4700:4700::1111", "::ffff:10.0.0.1"]])
    assert_equal :blocked, f.fetch("https://records.example.org/?format=json").kind
  end

  def test_refuses_metadata_and_link_local
    f, = fetcher([:ok, ["169.254.169.254"]])
    assert_equal :blocked, f.fetch("https://metadata.example.org/").kind
    f, = fetcher([:ok, ["fe80::1"]])
    assert_equal :blocked, f.fetch("https://metadata.example.org/").kind
  end

  def test_no_address_and_lookup_failure
    f, = fetcher([:ok, []])
    assert_equal :no_address, f.fetch("https://records.example.org/").kind
    f, = fetcher([:error, :servfail])
    assert_equal :dns_error, f.fetch("https://records.example.org/").kind
  end

  def test_refuses_before_any_lookup
    [
      "http://records.example.org/",
      "https://records.example.org:8443/",
      "https://user@records.example.org/",
      "https://127.0.0.1/",
      "https://[::1]/",
      "https://2130706433/",
      "https://printer.local/",
      "https://svc.internal/",
      "https://localhost/",
      "ftp://records.example.org/"
    ].each do |url|
      f, resolver = fetcher([:ok, ["93.184.215.14"]])
      assert_equal :blocked, f.fetch(url).kind, url
      assert_empty resolver.asked, url
    end
  end

  # --- the HTTPS path, against a local server ---------------------------------------------------

  def make_ca_and_leaf(name)
    ca_key = OpenSSL::PKey::EC.generate("prime256v1")
    ca = OpenSSL::X509::Certificate.new
    ca.version = 2
    ca.serial = 1
    ca.subject = ca.issuer = OpenSSL::X509::Name.parse("/CN=abiz test CA")
    ca.public_key = ca_key
    ca.not_before = Time.now - 60
    ca.not_after = Time.now + 3600
    ef = OpenSSL::X509::ExtensionFactory.new(ca, ca)
    ca.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
    ca.add_extension(ef.create_extension("keyUsage", "keyCertSign,cRLSign", true))
    ca.sign(ca_key, "SHA256")

    key = OpenSSL::PKey::EC.generate("prime256v1")
    leaf = OpenSSL::X509::Certificate.new
    leaf.version = 2
    leaf.serial = 2
    leaf.subject = OpenSSL::X509::Name.parse("/CN=#{name}")
    leaf.issuer = ca.subject
    leaf.public_key = key
    leaf.not_before = Time.now - 60
    leaf.not_after = Time.now + 3600
    ef = OpenSSL::X509::ExtensionFactory.new(ca, leaf)
    leaf.add_extension(ef.create_extension("subjectAltName", "DNS:#{name}", false))
    leaf.sign(ca_key, "SHA256")
    [ca, leaf, key]
  end

  # One TLS server on 127.0.0.1 answering each connection with +response+. Records the SNI name
  # and the request head it saw.
  def with_server(name, response)
    ca, leaf, key = make_ca_and_leaf(name)
    tcp = TCPServer.new("127.0.0.1", 0)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.cert = leaf
    ctx.key = key
    seen = { sni: nil, head: nil }
    ctx.servername_cb = lambda do |(sock, servername)|
      seen[:sni] = servername
      sock.context
    end
    server = OpenSSL::SSL::SSLServer.new(tcp, ctx)
    thread = Thread.new do
      conn = server.accept
      head = +""
      head << conn.readpartial(4096) until head.include?("\r\n\r\n")
      seen[:head] = head
      conn.write(response)
      conn.close
    rescue StandardError
      nil
    end
    store = OpenSSL::X509::Store.new
    store.add_cert(ca)
    yield tcp.addr[1], store, seen
  ensure
    thread&.join(2)
    thread&.kill
    tcp&.close
  end

  def direct_get(port, store, host: "records.example.org", target: "/acme?format=json")
    f = Abiz::Http::GuardedFetcher.new(resolver: StubResolver.new([:ok, []]), cert_store: store)
    f.instance_variable_set(:@port, port)
    f.send(:get, host, "127.0.0.1", target)
  end

  def test_connects_to_the_checked_address_with_the_name_for_sni_and_host
    body = '{"ok":true}'
    response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}"
    with_server("records.example.org", response) do |port, store, seen|
      out = direct_get(port, store)
      assert_equal :response, out.kind
      assert_equal 200, out.status
      assert_equal "application/json", out.content_type
      assert_equal body, out.body
      assert_equal "records.example.org", seen[:sni]
      assert_match(%r{\AGET /acme\?format=json HTTP/1.1\r\n}, seen[:head])
      assert_match(/^Host: records\.example\.org(:\d+)?\r$/i, seen[:head])
      assert_match(%r{^Accept: application/json\r$}i, seen[:head])
      assert_match(%r{^User-Agent: abiz-ruby/2026\.1116\.1 \(\+https://abizrecord\.org\)\r$}i, seen[:head])
    end
  end

  def test_a_certificate_for_another_name_is_refused
    with_server("someone-else.example.org", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}") do |port, store, _seen|
      assert_equal :network, direct_get(port, store).kind
    end
  end

  def test_an_untrusted_certificate_is_refused
    with_server("records.example.org", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}") do |port, _store, _seen|
      assert_equal :network, direct_get(port, OpenSSL::X509::Store.new).kind
    end
  end

  def test_a_redirect_is_reported_not_followed
    response = "HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example.org/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    with_server("records.example.org", response) do |port, store, _seen|
      out = direct_get(port, store)
      assert_equal :response, out.kind
      assert_equal 302, out.status
    end
  end

  def test_a_body_over_64_kib_is_cut_off
    body = "x" * 70_000
    response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}"
    with_server("records.example.org", response) do |port, store, _seen|
      out = direct_get(port, store)
      assert_equal 200, out.status
      assert_nil out.body
    end
  end
end
