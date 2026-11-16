# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "jekyll-abiz"
require "minitest/autorun"
require "tmpdir"
require "stringio"
require "fileutils"

class GeneratorTest < Minitest::Test
  P1 = "VWQYaWGhH5gcAwj/7ee6AnHsL1xzNlr4QdScICqIgjc="

  def build(settings, extra_files = {}, quiet: true)
    Dir.mktmpdir("jekyll-abiz") do |dir|
      source = File.join(dir, "src")
      dest = File.join(dir, "_site")
      FileUtils.mkdir_p(source)
      File.write(File.join(source, "index.md"), "---\ntitle: Home\n---\nHello\n")
      extra_files.each do |path, content|
        FileUtils.mkdir_p(File.dirname(File.join(source, path)))
        File.write(File.join(source, path), content)
      end
      config = { "source" => source, "destination" => dest, "quiet" => quiet, "plugins" => ["jekyll-abiz"] }
      config["abiz"] = settings unless settings == :none
      config["include"] = [".well-known"] if extra_files.keys.any? { |p| p.start_with?(".well-known") }
      site = Jekyll::Site.new(Jekyll.configuration(config))
      site.process
      file = File.join(dest, ".well-known", "abiz.json")
      return File.exist?(file) ? File.read(file) : nil
    end
  end

  def test_writes_the_pointer
    text = build({ "h" => "records.example.org/acme", "k" => "gb-01234567", "p" => P1 })
    refute_nil text
    document = JSON.parse(text)
    assert_equal({ "v" => "abiz1", "k" => "gb-01234567", "h" => "records.example.org/acme", "p" => P1 }, document)
    assert_equal %w[v k h p], document.keys
    # A consumer reads it back as the same assertion.
    tags, = Abiz::AssertionParser.text_from_well_known(document)
    parsed = Abiz.parse_assertion(tags)
    assert parsed.ok?
    assert_equal "records.example.org/acme", parsed.assertion.h
  end

  def test_k_is_optional
    document = JSON.parse(build({ "h" => "records.example.org", "p" => P1 }))
    assert_equal({ "v" => "abiz1", "h" => "records.example.org", "p" => P1 }, document)
  end

  def test_nothing_without_settings
    assert_nil build(:none)
  end

  def test_invalid_values_fail_the_build
    {
      { "h" => "records.example.org", "p" => "5564186961a11f981c0308ffede7ba0271ec2f5c73365af841d49c202a888237" } => /schema_invalid|invalid_key/,
      { "h" => "https://records.example.org", "p" => P1 } => /not a valid ABIZ pointer/,
      { "h" => "printer.local", "p" => P1 } => /unsafe_host/,
      { "h" => "records.example.org", "p" => P1, "k" => "zz-123" } => /not a valid ABIZ pointer/,
      { "h" => "records.example.org" } => /abiz\.p is required/,
      { "p" => P1 } => /abiz\.h is required/,
      { "h" => "records.example.org", "p" => P1, "k" => 123 } => /abiz\.k must be a string/,
      "records.example.org" => /must be a mapping/
    }.each do |settings, message|
      error = assert_raises(Jekyll::Abiz::ConfigError, settings.inspect) { build(settings) }
      assert_match message, error.message, settings.inspect
    end
  end

  def test_refuses_private_key_settings
    %w[private_key seed secret signing_key d].each do |name|
      error = assert_raises(Jekyll::Abiz::ConfigError) { build({ "h" => "records.example.org", "p" => P1, name => "x" }) }
      assert_match(/never put a private key/i, error.message)
    end
  end

  def test_refuses_a_second_pointer
    error = assert_raises(Jekyll::Abiz::ConfigError) do
      build({ "h" => "records.example.org", "p" => P1 }, { ".well-known/abiz.json" => "{}" })
    end
    assert_match(/already has a file/, error.message)
  end

  def test_prints_the_txt_value_when_asked
    out = StringIO.new
    logger = Jekyll.logger
    Jekyll.instance_variable_set(:@logger, Jekyll::LogAdapter.new(Logger.new(out), :info))
    begin
      build({ "h" => "records.example.org", "p" => P1, "k" => "gb-01234567", "print_txt" => true }, quiet: false)
    ensure
      Jekyll.instance_variable_set(:@logger, logger)
    end
    assert_includes out.string, "_abiz TXT value: v=abiz1;k=gb-01234567;h=records.example.org;p=#{P1}"
  end
end
