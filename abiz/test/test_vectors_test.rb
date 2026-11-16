# frozen_string_literal: true

require_relative "test_helper"

# Every case in every shared vector file is its own test, so a failure names the case. A case
# counts towards the per-file total only once its assertions have passed.
class AssertionVectorsTest < Minitest::Test
  VectorHelper.load("assertions.json")["cases"].each_with_index do |c, i|
    define_method("test_#{i}_#{c["name"]}") do
      assert_equal c["is_assertion"], Abiz.assertion?(c["value"]), "is_assertion"
      result = Abiz.parse_assertion(c["value"])
      if c["ok"]
        assert result.ok?, "expected ok, got #{result.code}: #{result.message}"
        assert_equal c["h"], result.assertion.h
        assert_same_value c["k"], result.assertion.k
        assert_equal c["p"], result.assertion.p
      else
        refute result.ok?, "expected #{c["code"]}"
        assert_equal c["code"], result.code
      end
      VectorHelper.count("assertions.json")
    end
  end
end

class PublicKeyVectorsTest < Minitest::Test
  VectorHelper.load("public-keys.json")["cases"].each_with_index do |c, i|
    define_method("test_#{i}") do
      assert_equal c["ok"], Abiz.public_key?(c["value"]), c["value"].inspect
      VectorHelper.count("public-keys.json")
    end
  end
end

class HostVectorsTest < Minitest::Test
  data = VectorHelper.load("hosts.json")
  data["identity"].each_with_index do |c, i|
    define_method("test_identity_#{i}") do
      if c["canonical"].nil?
        assert_nil Abiz.identity_host(c["value"]), c["value"]
      else
        assert_equal c["canonical"], Abiz.identity_host(c["value"]), c["value"]
      end
      VectorHelper.count("hosts.json")
    end
  end
  data["inputs"].each_with_index do |c, i|
    define_method("test_input_#{i}") do
      input = c["input"]
      out = Abiz.normalize_input(domain: input["domain"], website: input["website"])
      if c["ok"]
        assert_equal [:ok, c["domain"]], out, input.inspect
      else
        assert_equal :error, out[0], "#{input.inspect} gave #{out.inspect}"
        assert_equal c["code"], out[1], input.inspect
      end
      VectorHelper.count("hosts.json")
    end
  end
end

class AddressVectorsTest < Minitest::Test
  VectorHelper.load("addresses.json")["cases"].each_with_index do |c, i|
    define_method("test_#{i}_#{c["address"]}") do
      assert_equal c["public"], Abiz.public_address?(c["address"]), c["address"]
      VectorHelper.count("addresses.json")
    end
  end
end

class JcsVectorsTest < Minitest::Test
  VectorHelper.load("jcs.json")["cases"].each_with_index do |c, i|
    define_method("test_#{i}_#{c["name"]}") do
      out = Abiz.canonicalize(c["input"], json_text: true)
      assert_equal c["output"].b, out.b
      VectorHelper.count("jcs.json")
    end
  end
end

class SigningVectorsTest < Minitest::Test
  data = VectorHelper.load("signing.json")
  KEYS = data["test_keys"]

  data["cases"].each_with_index do |c, i|
    define_method("test_#{i}_#{c["name"]}") do
      assert_equal c["signing_input"].b, Abiz.signing_input(c["record_text"])
      record = Abiz::JsonText.parse(c["record_text"])
      check = Abiz.verify_signature(record, record["public_key"])
      assert_equal c["verifies"], check.ok?, check.message
      assert_equal "signature_invalid", check.code unless c["verifies"]
      VectorHelper.count("signing.json")
    end
  end

  KEYS.each_with_index do |key, i|
    define_method("test_key_#{i}_public_half") do
      pkey = Abiz::Signature.private_key([key["seed_hex"]].pack("H*"))
      assert_equal key["public_key"], Abiz::Signature.public_key_base64(pkey)
    end
  end

  def test_sign_record_reproduces_the_vector_signature
    c = VectorHelper.load("signing.json")["cases"].find { |x| x["name"] == "test key 1 sample" }
    record = Abiz::JsonText.parse(c["record_text"])
    seed = [KEYS[0]["seed_hex"]].pack("H*")
    signed = Abiz.sign_record(record.reject { |k, _| k == "signature" }, seed)
    assert_equal record["signature"], signed["signature"]
    assert Abiz.verify_signature(signed, KEYS[0]["public_key"]).ok?
  end
end

class RecordVectorsTest < Minitest::Test
  VectorHelper.load("records.json")["cases"].each_with_index do |c, i|
    define_method("test_#{i}_#{c["name"]}") do
      code, problems = Abiz.check_record_details(c["record_text"], c["domain"], c["assertion"])
      assert_same_value c["expect"], code, "#{c["name"]}: #{problems.map { |p| "#{p.path} #{p.message}" }.join("; ")}"
      VectorHelper.count("records.json")
    end
  end
end
