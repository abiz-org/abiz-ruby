# frozen_string_literal: true

require_relative "test_helper"
require "digest"

# Checks outside the shared vectors: the bundled files, strict JSON, JCS edge cases, the schema
# options, the producer helpers and the public API's shape.
class BundledFilesTest < Minitest::Test
  README = File.read(File.join(VectorHelper::VECTORS, "README.md"))

  Abiz::Schema::SHA256.each do |path, sha|
    define_method("test_sha256_#{File.basename(path)}") do
      assert_equal sha, Digest::SHA256.file(path).hexdigest, path
      # The pinned value is the one the shared vectors' README publishes.
      assert_includes README, sha
      # And the bundled copy is byte for byte the vectors' own file.
      vector_copy = path.sub(%r{.*/data/}, "#{VectorHelper::VECTORS}/").sub("/schemas/", "/schemas/")
      vector_copy = File.join(VectorHelper::VECTORS, "data", "iso3166.json") if path.end_with?("iso3166.json")
      assert_equal File.binread(vector_copy), File.binread(path)
    end
  end
end

class JsonTextTest < Minitest::Test
  def test_repeated_member_is_reported_with_its_pointer
    error = assert_raises(Abiz::JsonText::DuplicateMember) { Abiz::JsonText.parse('{"a":{"b/c":1,"b/c":2}}') }
    assert_equal "/a/b~1c", error.pointer
    # The same name after unescaping is a repeat too.
    assert_raises(Abiz::JsonText::DuplicateMember) { Abiz::JsonText.parse('{"a":1,"a":2}') }
  end

  def test_rejects_what_rfc_8259_rejects
    ['{"a":1,}', "[1,]", "/*c*/{}", '{"a":NaN}', "[01]", '{"a":"x' + "\t" + 'y"}', "﻿{}", "{} x", "", '{"a":"\ud800"}'].each do |text|
      assert_raises(Abiz::JsonText::ParseError, text.inspect) { Abiz::JsonText.parse(text) }
    end
  end

  def test_numbers
    assert_equal [1, 1.5, 100.0, -0.0], Abiz::JsonText.parse("[1, 1.5, 1E2, -0.0]")
    assert_kind_of Integer, Abiz::JsonText.parse("9007199254740993")
  end

  def test_shape_limits
    assert_equal :too_deep, Abiz::JsonText.shape_problem(("[" * 17) + ("]" * 17))
    assert_nil Abiz::JsonText.shape_problem(("[" * 16) + ("]" * 16))
    many = "{" + (1..5001).map { |i| "\"k#{i}\":0" }.join(",") + "}"
    assert_equal :too_many_keys, Abiz::JsonText.shape_problem(many)
    # Characters inside strings do not count.
    assert_nil Abiz::JsonText.shape_problem('{"a":"[[[[[[[[[[[[[[[[[[[[:::"}')
  end
end

class JcsTest < Minitest::Test
  def test_refuses_non_finite_numbers
    assert_raises(Abiz::JCS::Error) { Abiz.canonicalize([Float::INFINITY]) }
    assert_raises(Abiz::JCS::Error) { Abiz.canonicalize([Float::NAN]) }
  end

  def test_refuses_invalid_strings_and_keys
    assert_raises(Abiz::JCS::Error) { Abiz.canonicalize(["\xED\xA0\x80".b.force_encoding("UTF-8")]) }
    assert_raises(Abiz::JCS::Error) { Abiz.canonicalize({ 1 => 2 }) }
  end

  def test_large_integers_are_doubles
    assert_equal "[1e+21,9007199254740992]", Abiz.canonicalize([10**21, 9_007_199_254_740_993])
  end
end

class SchemaOptionsTest < Minitest::Test
  def test_formats_are_asserted
    v = Abiz::Schema.record_validator
    refute v.valid?({ "last_updated" => "yesterday" }.merge(minimal)), "date-time is asserted"
  end

  def test_patterns_are_ecmascript
    # business_name has "pattern": "\S". In ECMAScript a no-break space is whitespace; in a Ruby
    # regular expression \S matches it. A name of only no-break spaces must fail.
    assert Abiz::Schema.record_validator.valid?(minimal), "the minimal record is valid"
    refute Abiz::Schema.record_validator.valid?(minimal.merge("business_name" => "\u00a0\u00a0"))
  end

  def minimal
    {
      "record_version" => "abiz1", "business_name" => "Example", "country" => { "code" => "GB", "name" => "United Kingdom" },
      "identity_host" => "records.example.org", "domains" => ["example.org"],
      "public_key" => "VWQYaWGhH5gcAwj/7ee6AnHsL1xzNlr4QdScICqIgjc=", "signature" => ("A" * 86) + "=="
    }
  end
end

class ProducerHelpersTest < Minitest::Test
  KEY1 = ["edcb87f24a87794d432f17cd60a9a864609ff2592a03108dd2c95c0e28eabc78"].pack("H*")
  P1 = "VWQYaWGhH5gcAwj/7ee6AnHsL1xzNlr4QdScICqIgjc="

  def test_sign_then_check_round_trip
    record = {
      "record_version" => "abiz1", "business_name" => "Example Ltd", "country" => { "code" => "GB", "name" => "United Kingdom" },
      "business_key" => "gb-01234567", "registration_number" => "01234567",
      "identity_host" => "records.example.org/example", "domains" => ["example.org"]
    }
    signed = Abiz.sign_record(record, KEY1)
    assert_equal P1, signed["public_key"]
    text = JSON.generate(signed)
    assert_nil Abiz.check_record(text, "example.org", "v=abiz1;k=gb-01234567;h=records.example.org/example;p=#{P1}")
    tampered = JSON.generate(signed.merge("business_name" => "Someone Else Ltd"))
    assert_equal "signature_invalid", Abiz.check_record(tampered, "example.org", "v=abiz1;h=records.example.org/example;p=#{P1}")
  end

  def test_txt_value_and_well_known_document
    assert_equal "v=abiz1;k=gb-01234567;h=records.example.org;p=#{P1}", Abiz.txt_value(h: "records.example.org", p: P1, k: "gb-01234567")
    doc, code = Abiz.well_known_document(h: "records.example.org", p: P1, k: "gb-01234567")
    assert_nil code
    assert_equal({ "v" => "abiz1", "k" => "gb-01234567", "h" => "records.example.org", "p" => P1 }, doc)
    _doc, code = Abiz.well_known_document(h: "records.example.org", p: "not-a-key")
    assert_equal "schema_invalid", code
    _doc, code = Abiz.well_known_document(h: "printer.local", p: P1)
    assert_equal "unsafe_host", code
    _doc, code = Abiz.well_known_document(h: "records.example.org", p: P1, k: "zz-123")
    assert_equal "bad_pointer", code
  end

  def test_verify_signature_api
    c = VectorHelper.load("signing.json")["cases"].first
    assert Abiz.verify_signature(c["record_text"], JSON.parse(c["record_text"])["public_key"]).ok?
    assert_equal "public_key_mismatch", Abiz.verify_signature(c["record_text"], P1).code
  end
end

class ResolveDefaultsTest < Minitest::Test
  # resolve() refuses bad input before building any network adapter or sending anything.
  def test_invalid_input_needs_no_network
    result = Abiz.resolve("printer.local", dns: Object.new, http: Object.new)
    assert_equal "invalid_input", result.status
    assert_equal "non_public_domain", result.code
  end

  def test_never_fetches_mcp_server_url
    record = {
      "record_version" => "abiz1", "business_name" => "Example Ltd", "country" => { "code" => "GB", "name" => "United Kingdom" },
      "identity_host" => "records.example.org", "domains" => ["example.org"],
      "mcp_server_url" => "https://mcp.example.org/mcp"
    }
    body = JSON.generate(Abiz.sign_record(record, ProducerHelpersTest::KEY1))
    fetched = []
    dns = Struct.new(:x) do
      def query_txt(_name) = Abiz::TxtLookup.answer(["v=abiz1;h=records.example.org;p=#{ProducerHelpersTest::P1}"])
    end.new
    http = Object.new
    http.define_singleton_method(:fetch) do |url|
      fetched << url
      Abiz::FetchOutcome.response(200, "application/json", body)
    end
    result = Abiz.resolve("example.org", dns: dns, http: http)
    assert result.resolved?, result.details.inspect
    assert_equal ["https://records.example.org?format=json"], fetched
  end
end
