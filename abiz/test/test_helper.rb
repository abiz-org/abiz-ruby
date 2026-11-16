# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "abiz"
require "json"
require "minitest/autorun"

module VectorHelper
  # The shared vectors: ABIZ_VECTORS overrides the location (for a copy outside the repository).
  VECTORS = ENV.fetch("ABIZ_VECTORS", File.expand_path("../../test-vectors", __dir__))

  def self.load(name)
    data = JSON.parse(File.read(File.join(VECTORS, name), mode: "rb").force_encoding(Encoding::UTF_8))
    raise "#{name}: unexpected format #{data["format"]}" unless data["format"] == Abiz::TEST_VECTOR_FORMAT

    data
  end

  # Count of vectors run, per file, printed at exit.
  COUNTS = Hash.new(0)

  def self.count(file)
    COUNTS[file] += 1
  end
end

module Minitest
  class Test
    # assert_equal, or assert_nil when nil is expected.
    def assert_same_value(expected, actual, message = nil)
      expected.nil? ? assert_nil(actual, message) : assert_equal(expected, actual, message)
    end
  end
end

Minitest.after_run do
  unless VectorHelper::COUNTS.empty?
    puts
    puts "Vectors passed per file:"
    VectorHelper::COUNTS.sort.each { |file, n| puts "  #{file}: #{n}" }
    puts "  total: #{VectorHelper::COUNTS.values.sum}"
  end
end
