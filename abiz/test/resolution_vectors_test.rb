# frozen_string_literal: true

require_relative "test_helper"

# resolution.json: the whole algorithm against a fake DNS and a fake fetch, recording every request.
class ResolutionVectorsTest < Minitest::Test
  class FakeDns
    attr_reader :queries

    def initialize(table)
      @table = table
      @queries = []
    end

    def query_txt(name)
      @queries << name
      entry = @table[name]
      return Abiz::TxtLookup.nxdomain if entry.nil?

      case entry["kind"]
      when "answer" then Abiz::TxtLookup.answer(entry["values"], ttl: entry["ttl"])
      when "nxdomain" then Abiz::TxtLookup.nxdomain(ttl: entry["ttl"])
      when "nodata" then Abiz::TxtLookup.nodata(ttl: entry["ttl"])
      when "error" then Abiz::TxtLookup.error(entry["reason"].to_sym)
      else raise "unknown DNS kind #{entry["kind"]}"
      end
    end
  end

  class FakeHttp
    attr_reader :fetches

    def initialize(table)
      @table = table
      @fetches = []
    end

    def fetch(url)
      @fetches << url
      entry = @table[url]
      return Abiz::FetchOutcome.response(404, "text/plain", "Not found") if entry.nil?

      case entry["kind"]
      when "response" then Abiz::FetchOutcome.response(entry["status"], entry["content_type"], entry["body"])
      when "blocked" then Abiz::FetchOutcome.blocked(entry["message"] || "blocked")
      when "no_address" then Abiz::FetchOutcome.no_address
      when "dns_error" then Abiz::FetchOutcome.dns_error
      when "timeout" then Abiz::FetchOutcome.timeout
      when "network" then Abiz::FetchOutcome.network
      else raise "unknown fetch kind #{entry["kind"]}"
      end
    end
  end

  VectorHelper.load("resolution.json")["cases"].each_with_index do |c, i|
    define_method("test_#{i}_#{c["name"]}") do
      dns = FakeDns.new(c["dns"])
      http = FakeHttp.new(c["http"])
      input = c["input"]
      result = Abiz.resolve(input["domain"], website: input["website"], dns: dns, http: http)
      e = c["expect"]
      assert_equal e["status"], result.status
      assert_same_value e["code"], result.code, result.details.map(&:message).join("; ")
      assert_equal e["retryable"], result.retryable
      if e.key?("method")
        assert_equal e["method"], result.discovery.method
        assert_equal e["well_known"], result.discovery.well_known
      else
        assert_nil result.discovery
      end
      if e.key?("dns_value")
        assert_equal e["dns_value"], result.discovery.dns_value
      elsif result.discovery
        assert_nil result.discovery.dns_value
      end
      if e.key?("domain")
        assert_equal e["domain"], result.domain
      else
        assert_nil result.domain
      end
      warnings = result.warnings.map { |w| w.domain ? { "code" => w.code, "domain" => w.domain } : { "code" => w.code } }
      assert_equal e["warnings"], warnings
      assert_equal e["record_returned"], !result.record.nil?
      assert_equal e["dns_queries"], dns.queries
      assert_equal e["fetches"], http.fetches
      VectorHelper.count("resolution.json")
    end
  end
end
