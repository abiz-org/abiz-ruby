# frozen_string_literal: true

require "json"
require "abiz"

module Jekyll
  module Abiz
    # Raised when the abiz: settings in _config.yml are invalid. The build stops.
    class ConfigError < Jekyll::Errors::FatalException; end

    # Writes /.well-known/abiz.json (ABIZ 1.1, SPEC section 3.4) from _config.yml:
    #
    #   abiz:
    #     h: records.example.org/acme      # the record host (required)
    #     p: VWQYaWGh...ICqIgjc=           # the Ed25519 PUBLIC key, base64 (required)
    #     k: gb-01234567                   # the business key (optional)
    #     print_txt: true                  # also log the matching _abiz TXT value (optional)
    #
    # The values are checked with the abiz gem exactly as a consumer reads them, and the build
    # fails with a clear message when they are invalid. The file is a pointer only: this plugin
    # never reads, holds or writes a private key, and refuses settings that look like one.
    class Generator < Jekyll::Generator
      safe true
      priority :lowest

      PATH = "/.well-known/abiz.json"
      ALLOWED = %w[h k p print_txt].freeze
      # Setting names that suggest private key material, which must never be in _config.yml.
      SECRET_NAMES = /private|secret|seed|signing|\Ad\z|\Ask\z|\Akey\z|pem|jwk/i

      def generate(site)
        settings = site.config["abiz"]
        return if settings.nil?

        values = self.class.check_settings(settings)
        if clash?(site)
          raise ConfigError, "jekyll-abiz: the site already has a file at #{PATH}. Remove it, or remove the abiz: settings from _config.yml, so that only one pointer is published."
        end

        document = self.class.document(values)
        page = Jekyll::PageWithoutAFile.new(site, site.source, ".well-known", "abiz.json")
        page.content = "#{JSON.pretty_generate(document)}\n"
        page.data["layout"] = nil
        page.data["sitemap"] = false
        page.data["render_with_liquid"] = false
        site.pages << page

        Jekyll.logger.info "ABIZ:", "wrote #{PATH} (h=#{values[:h]})"
        if settings["print_txt"] == true
          Jekyll.logger.info "ABIZ:", "_abiz TXT value: #{::Abiz.txt_value(h: values[:h], p: values[:p], k: values[:k])}"
        end
      end

      # Check the abiz: settings and return { h:, p:, k: }. Raises ConfigError with a clear message.
      def self.check_settings(settings)
        unless settings.is_a?(Hash)
          raise ConfigError, "jekyll-abiz: abiz: in _config.yml must be a mapping with h and p (and optionally k)."
        end

        secret = settings.keys.find { |key| key.to_s != "p" && key.to_s.match?(SECRET_NAMES) }
        if secret
          raise ConfigError, "jekyll-abiz: abiz.#{secret} looks like private key material. Never put a private key in _config.yml " \
                             "(it is committed and may be published). This plugin needs only the public key, p."
        end
        unknown = settings.keys.map(&:to_s) - ALLOWED
        Jekyll.logger.warn "ABIZ:", "ignoring unknown setting(s) abiz.#{unknown.join(", abiz.")}" unless unknown.empty?

        values = {}
        %w[h p k].each do |name|
          next unless settings.key?(name)

          value = settings[name]
          unless value.is_a?(String)
            raise ConfigError, "jekyll-abiz: abiz.#{name} must be a string (put quotes around it in _config.yml); found #{value.inspect}."
          end

          values[name.to_sym] = value
        end
        raise ConfigError, "jekyll-abiz: abiz.h is required: the record host, for example records.example.org/acme." unless values[:h]
        raise ConfigError, "jekyll-abiz: abiz.p is required: the business's Ed25519 public key, 44 characters of standard base64." unless values[:p]

        _document, code, message = ::Abiz.well_known_document(h: values[:h], p: values[:p], k: values[:k])
        raise ConfigError, "jekyll-abiz: the abiz settings are not a valid ABIZ pointer (#{code}): #{message}" if code

        values
      end

      # The /.well-known/abiz.json document: v, k (when set), h and p, each a JSON string.
      def self.document(values)
        document, = ::Abiz.well_known_document(h: values[:h], p: values[:p], k: values[:k])
        document
      end

      private

      def clash?(site)
        site.pages.any? { |page| page.url == PATH } || site.static_files.any? { |file| file.url == PATH }
      end
    end
  end
end
