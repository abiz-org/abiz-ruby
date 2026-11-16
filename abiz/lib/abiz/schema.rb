# frozen_string_literal: true

require "json"
require "json_schemer"

module Abiz
  # The normative ABIZ 1.1 schemas, bundled byte for byte and pinned by SHA-256 (a test checks
  # them). They are copies of abiz-org/abiz-agentic-business-record at commit
  # 3fb26a34e3cb1402a28352b5071a150e87853d5c (tag v1.1.0), as are the shared test vectors.
  module Schema
    DATA_DIR = File.expand_path("data", __dir__)
    RECORD_PATH = File.join(DATA_DIR, "schemas", "abiz-business-record-v1.1.schema.json")
    WELL_KNOWN_PATH = File.join(DATA_DIR, "schemas", "abiz-well-known-v1.1.schema.json")
    ISO3166_PATH = File.join(DATA_DIR, "iso3166.json")

    RECORD_ID = "https://abizrecord.org/schema/abiz-business-record-v1.1.schema.json"
    WELL_KNOWN_ID = "https://abizrecord.org/schema/abiz-well-known-v1.1.schema.json"

    SHA256 = {
      RECORD_PATH => "3658f17f00c238b8c948fdfb447b509c5d055dd778ebd335495da05c3150ff24",
      WELL_KNOWN_PATH => "5fe7da6fb5b6b262281402ab9dd9b46c018bf9df766203928e4e1a334cc3d741",
      ISO3166_PATH => "0aa5112c46bc2b3efb254ea9536b3cf2977c73d48149aefcd8bc20df995e5527"
    }.freeze

    SOURCE = "https://github.com/abiz-org/abiz-agentic-business-record/tree/3fb26a34e3cb1402a28352b5071a150e87853d5c"

    module_function

    def load(path)
      JSON.parse(File.read(path, mode: "rb").force_encoding(Encoding::UTF_8))
    end
    private_class_method :load

    # The reference validators' "hostname" (ASCII labels, one optional trailing dot, any case).
    # json_schemer's own check refuses a trailing dot, which both references accept.
    HOSTNAME = /\A(?=.{1,253}\.?\z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[-0-9a-z]{0,61}[0-9a-z])?)*\.?\z/i
    FORMATS = {
      "hostname" => ->(instance, _format) { !instance.is_a?(String) || instance.match?(HOSTNAME) }
    }.freeze

    # Draft 2020-12 with format asserted and ECMAScript regular expressions, as the reference
    # validators run it.
    def compile(path)
      JSONSchemer.schema(load(path), format: true, formats: FORMATS, regexp_resolver: "ecma")
    end
    private_class_method :compile

    def record_validator
      @record_validator ||= compile(RECORD_PATH)
    end

    def well_known_validator
      @well_known_validator ||= compile(WELL_KNOWN_PATH)
    end

    # Schema problems for +instance+ as [{path:, message:}], empty when valid.
    def record_problems(instance)
      problems(record_validator, instance)
    end

    def well_known_problems(instance)
      problems(well_known_validator, instance)
    end

    def problems(validator, instance)
      out = []
      seen = {}
      validator.validate(instance).each do |error|
        path = error["data_pointer"].to_s
        path = "$" if path.empty?
        message = error["error"].to_s[0, 300]
        key = "#{path}\n#{message}"
        next if seen[key]

        seen[key] = true
        out << { path: path, message: message }
      end
      out
    end
    private_class_method :problems
  end
end
