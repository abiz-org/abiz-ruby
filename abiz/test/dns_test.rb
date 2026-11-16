# frozen_string_literal: true

require_relative "test_helper"
require "socket"

# The stub resolver against a local DNS server on 127.0.0.1: NXDOMAIN, NODATA, SERVFAIL, REFUSED
# and a timeout must stay distinct (Resolv::DNS#getresources returns [] for all of them).
class DnsStubTest < Minitest::Test
  TXT = Resolv::DNS::Resource::IN::TXT
  A = Resolv::DNS::Resource::IN::A

  # Runs a DNS server answering each query with handler's result (a Resolv::DNS::Message, :drop
  # for no reply, or a String of raw bytes) and yields a stub resolver pointed at it.
  def with_server(handler)
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    port = socket.addr[1]
    thread = Thread.new do
      loop do
        data, from = socket.recvfrom(4096)
        reply = handler.call(Resolv::DNS::Message.decode(data))
        next if :drop.equal?(reply)

        bytes = reply.is_a?(String) ? reply : reply.encode
        socket.send(bytes, 0, from[3], from[1])
      end
    rescue IOError
      nil
    end
    yield Abiz::Dns::Stub.new(nameservers: [["127.0.0.1", port]], timeout: 0.5)
  ensure
    thread&.kill
    socket&.close
  end

  def reply_for(query, rcode: 0)
    reply = Resolv::DNS::Message.new(query.id)
    reply.qr = 1
    reply.rd = 1
    reply.ra = 1
    reply.rcode = rcode
    query.question.each { |name, type| reply.add_question(name, type) }
    reply
  end

  def test_answer_joins_character_strings
    handler = lambda do |q|
      r = reply_for(q)
      r.add_answer(q.question.first[0], 300, TXT.new("v=abiz1;h=records.example.org;", "p=VWQYaWGhH5gcAwj/7ee6AnHsL1xzNlr4QdScICqIgjc="))
      r.add_answer(q.question.first[0], 120, TXT.new("v=spf1 -all"))
      r
    end
    with_server(handler) do |stub|
      lookup = stub.query_txt("_abiz.example.org")
      assert_equal :answer, lookup.kind
      assert_equal ["v=abiz1;h=records.example.org;p=VWQYaWGhH5gcAwj/7ee6AnHsL1xzNlr4QdScICqIgjc=", "v=spf1 -all"], lookup.values
      assert_equal 120, lookup.ttl
    end
  end

  def test_rcodes_stay_distinct
    {
      Resolv::DNS::RCode::NXDomain => [:nxdomain, nil],
      Resolv::DNS::RCode::ServFail => [:error, :servfail],
      Resolv::DNS::RCode::Refused => [:error, :refused],
      Resolv::DNS::RCode::NotImp => [:error, :malformed]
    }.each do |rcode, (kind, reason)|
      with_server(->(q) { reply_for(q, rcode: rcode) }) do |stub|
        lookup = stub.query_txt("_abiz.example.org")
        assert_equal kind, lookup.kind, "rcode #{rcode}"
        assert_same_value reason, lookup.reason
      end
    end
  end

  def test_nodata
    with_server(->(q) { reply_for(q) }) do |stub|
      assert_equal :nodata, stub.query_txt("_abiz.example.org").kind
    end
  end

  def test_timeout_is_not_absence
    with_server(->(_q) { :drop }) do |stub|
      lookup = stub.query_txt("_abiz.example.org")
      assert_equal :error, lookup.kind
      assert_equal :timeout, lookup.reason
    end
  end

  def test_a_reply_with_another_id_is_ignored
    handler = lambda do |q|
      r = reply_for(q)
      r.id = (q.id + 1) % 0x10000
      r
    end
    with_server(handler) do |stub|
      assert_equal :timeout, stub.query_txt("_abiz.example.org").reason
    end
  end

  def test_a_malformed_reply
    with_server(->(q) { [q.id].pack("n") + "\x81\x80\x00\x01".b }) do |stub|
      assert_equal :malformed, stub.query_txt("_abiz.example.org").reason
    end
  end

  def test_addresses
    handler = lambda do |q|
      r = reply_for(q)
      r.add_answer(q.question.first[0], 60, A.new("93.184.215.14")) if q.question.first[1] == A
      r
    end
    with_server(handler) do |stub|
      assert_equal [:ok, ["93.184.215.14"]], stub.addresses("records.example.org")
    end
  end

  def test_addresses_nxdomain_is_empty_and_servfail_an_error
    with_server(->(q) { reply_for(q, rcode: Resolv::DNS::RCode::NXDomain) }) do |stub|
      assert_equal [:ok, []], stub.addresses("records.example.org")
    end
    with_server(->(q) { reply_for(q, rcode: Resolv::DNS::RCode::ServFail) }) do |stub|
      assert_equal :error, stub.addresses("records.example.org")[0]
    end
  end

  def test_queries_an_absolute_name
    asked = []
    handler = lambda do |q|
      asked << q.question.first[0]
      reply_for(q, rcode: Resolv::DNS::RCode::NXDomain)
    end
    with_server(handler) { |stub| stub.query_txt("_abiz.example.org") }
    assert_equal ["_abiz.example.org"], asked.map(&:to_s)
  end

  def test_decode_txt_data_from_doh_json
    assert_equal "v=abiz1;h=a.example;p=x", Abiz::Dns.decode_txt_data('"v=abiz1;h=a.example;" "p=x"')
    assert_equal "say \"hi\"\\", Abiz::Dns.decode_txt_data('"say \"hi\"\\\\"')
    assert_equal "A", Abiz::Dns.decode_txt_data('"\\065"')
    assert_equal "unquoted value", Abiz::Dns.decode_txt_data("unquoted value")
  end
end
