# frozen_string_literal: true

require "set"
require "time"
require "tzinfo"
require_relative "host"
require_relative "business_key"
require_relative "schema"

module Abiz
  # The record checks JSON Schema cannot express (SPEC sections 4.4 and 4.7.13), reported as
  # schema_invalid, and the cross-checks between the record, the queried domain and the assertion
  # (SPEC section 6). A port of the reference resolver's validate.ts and validate.py.
  module Validate
    DAYS = %w[monday tuesday wednesday thursday friday saturday sunday].freeze
    FORBIDDEN_KEYS = Set["recent_posts", "contact_email", "contact_phone"].freeze
    MAX_PROBLEMS = 25

    module_function

    # IANA time zone identifiers (zones and links), from tzinfo-data.
    def time_zones
      @time_zones ||= begin
        Set.new(TZInfo::Timezone.all_identifiers).freeze
      rescue StandardError
        Set.new.freeze
      end
    end

    def problem(path, message)
      { path: path, message: message }
    end
    private_class_method :problem

    def country_code_problem(code)
      return "\"#{code}\" is not an assigned ISO 3166-1 alpha-2 code." unless BusinessKey.assigned_country?(code)

      BusinessKey.country_support_problem(code)
    end

    def place_code_problem(code)
      country = code.split("-", 2).first || code
      assigned = country_code_problem(country)
      return assigned if assigned

      code.include?("-") ? BusinessKey.region_code_problem(code, country) : nil
    end

    def minutes(value)
      m = /\A(\d{2}):(\d{2})\z/.match(value)
      return nil unless m

      m[1].to_i * 60 + m[2].to_i
    end
    private_class_method :minutes

    def period_spans(periods, day_index)
      base = day_index.nil? ? 0 : day_index * 1440
      spans = []
      periods.each do |period|
        period = {} unless period.is_a?(Hash)
        opens = minutes(js_string(period["opens"]))
        closes = minutes(js_string(period["closes"]))
        return [nil, "a period is not a HH:MM time."] if opens.nil? || closes.nil?
        if closes == opens
          return [nil, "period #{js_string(period["opens"])}-#{js_string(period["closes"])} opens and closes at the same time."]
        end

        closes += 1440 if closes < opens
        spans << [base + opens, base + closes]
      end
      [spans, nil]
    end
    private_class_method :period_spans

    def periods_overlap?(spans, wrap = nil)
      ordered = spans.sort_by(&:first)
      unless wrap.nil?
        ordered = (ordered + ordered.select { |s| s[0] < 1440 }.map { |s| [s[0] + wrap, s[1] + wrap] }).sort_by(&:first)
      end
      ordered.each_with_index.any? { |span, i| i + 1 < ordered.length && ordered[i + 1][0] < span[1] }
    end
    private_class_method :periods_overlap?

    # String(value) as ECMAScript writes it, for the few places the reference stringifies a value.
    def js_string(value)
      case value
      when nil then "undefined"
      when String then value
      else value.to_s
      end
    end
    private_class_method :js_string

    def out_of_order?(opens)
      opens.each_with_index.any? { |value, i| i.positive? && utf16_less?(value, opens[i - 1]) }
    end
    private_class_method :out_of_order?

    def utf16_less?(a, b)
      (a.encode(Encoding::UTF_16BE).b <=> b.encode(Encoding::UTF_16BE).b).negative?
    end
    private_class_method :utf16_less?

    # SPEC section 4.7.6.4: time zone, ordered and non-overlapping periods, days and dates once.
    def opening_hour_problems(hours, where, out)
      zones = time_zones
      if !zones.empty? && hours["time_zone"].is_a?(String) && !zones.include?(hours["time_zone"])
        out << problem("#{where}/time_zone", "\"#{hours["time_zone"]}\" is not an IANA time zone.")
      end
      weekly = hours["weekly"].is_a?(Array) ? hours["weekly"] : []
      weekly_spans = []
      seen_days = Set.new
      overlapped = false
      weekly.each do |entry|
        entry = {} unless entry.is_a?(Hash)
        day = js_string(entry["day"])
        if seen_days.include?(day)
          out << problem("#{where}/weekly", "weekly lists #{day} more than once.")
          next
        end
        seen_days << day
        periods = entry["periods"].is_a?(Array) ? entry["periods"] : []
        opens = periods.map { |pd| js_string(pd.is_a?(Hash) ? pd["opens"] : nil) }
        out << problem("#{where}/weekly", "#{day}: periods are not in order of opens.") if out_of_order?(opens)
        day_index = DAYS.index(day)
        next if day_index.nil?

        spans, message = period_spans(periods, day_index)
        if message
          out << problem("#{where}/weekly", "#{day}: #{message}")
          next
        end
        if periods_overlap?(spans)
          overlapped = true
          out << problem("#{where}/weekly", "#{day}: periods overlap.")
        end
        weekly_spans.concat(spans)
      end
      if !overlapped && periods_overlap?(weekly_spans, 7 * 1440)
        out << problem("#{where}/weekly", "an overnight period overlaps the next day's hours.")
      end
      exceptions = hours["exceptions"].is_a?(Array) ? hours["exceptions"] : []
      seen_dates = Set.new
      exceptions.each do |entry|
        entry = {} unless entry.is_a?(Hash)
        date = js_string(entry["date"])
        if seen_dates.include?(date)
          out << problem("#{where}/exceptions", "exceptions lists #{date} more than once.")
          next
        end
        seen_dates << date
        periods = entry["periods"].is_a?(Array) ? entry["periods"] : []
        opens = periods.map { |pd| js_string(pd.is_a?(Hash) ? pd["opens"] : nil) }
        out << problem("#{where}/exceptions", "#{date}: periods are not in order of opens.") if out_of_order?(opens)
        spans, message = period_spans(periods, nil)
        if message
          out << problem("#{where}/exceptions", "#{date}: #{message}")
        elsif periods_overlap?(spans)
          out << problem("#{where}/exceptions", "#{date}: periods overlap.")
        end
      end
    end

    def https_problem(value, path, label, out)
      out << problem(path, "#{label} must be an https URL with a public DNS host name.") if value.is_a?(String) && !Host.safe_https_url?(value)
    end
    private_class_method :https_problem

    def listing_problems(holder, where, out)
      return unless holder["review_summaries"].is_a?(Array)

      platforms = Set.new
      holder["review_summaries"].each_with_index do |item, index|
        next unless item.is_a?(Hash)

        base = "#{where}/review_summaries/#{index}"
        rating = item["rating"]
        scale = item["rating_scale"]
        if rating.is_a?(Numeric) && scale.is_a?(Numeric) && rating > scale
          out << problem("#{base}/rating", "rating #{rating} exceeds rating_scale #{scale}.")
        end
        if item["platform"].is_a?(String)
          out << problem("#{base}/platform", "more than one summary for #{item["platform"]}.") if platforms.include?(item["platform"])
          platforms << item["platform"]
        end
        https_problem(item["source_url"], "#{base}/source_url", "source_url", out)
      end
    end
    private_class_method :listing_problems

    def area_problems(areas, where, out)
      return unless areas.is_a?(Array)

      areas.each_with_index do |area, index|
        next unless area.is_a?(Hash)

        if area["code"].is_a?(String)
          msg = place_code_problem(area["code"])
          out << problem("#{where}/#{index}/code", msg) if msg
        elsif area["country"].is_a?(String)
          msg = country_code_problem(area["country"])
          out << problem("#{where}/#{index}/country", msg) if msg
        end
      end
    end
    private_class_method :area_problems

    def forbidden_key_problems(value, path, out)
      case value
      when Array
        value.each_with_index { |item, index| forbidden_key_problems(item, "#{path}/#{index}", out) }
      when Hash
        value.each do |key, child|
          here = "#{path}/#{key}"
          out << problem(here, "#{key} is not allowed.") if FORBIDDEN_KEYS.include?(key)
          forbidden_key_problems(child, here, out)
        end
      end
    end
    private_class_method :forbidden_key_problems

    def social_problems(profiles, where, out)
      return unless profiles.is_a?(Hash)

      profiles.each { |network, url| https_problem(url, "#{where}/#{network}", network, out) }
    end
    private_class_method :social_problems

    def category_problems(categories, where, out)
      return unless categories.is_a?(Hash)

      check = lambda do |category, path|
        next unless category.is_a?(Hash)

        taxonomy = category["taxonomy"]
        https_problem(taxonomy, path, "taxonomy", out) if taxonomy.is_a?(String) && taxonomy.match?(%r{\Ahttps?://}i)
      end
      check.call(categories["primary"], "#{where}/primary/taxonomy")
      if categories["additional"].is_a?(Array)
        categories["additional"].each_with_index { |category, index| check.call(category, "#{where}/additional/#{index}/taxonomy") }
      end
    end
    private_class_method :category_problems

    def media_problems(items, out)
      return unless items.is_a?(Array)

      ids = Set.new
      positions = Set.new
      items.each_with_index do |item, index|
        next unless item.is_a?(Hash)

        if item["id"].is_a?(String)
          out << problem("/media/#{index}/id", "media id \"#{item["id"]}\" is not unique.") if ids.include?(item["id"])
          ids << item["id"]
        end
        if item["position"].is_a?(Numeric)
          pos = item["position"].to_f
          out << problem("/media/#{index}/position", "media position #{item["position"]} is not unique.") if positions.include?(pos)
          positions << pos
        end
        https_problem(item["url"], "/media/#{index}/url", "url", out)
        alt = item["alt_text"]
        if item["kind"] != "video" && item["decorative"] != true && (!alt.is_a?(String) || alt.gsub(Host::JS_WS_TRIM, "").empty?)
          out << problem("/media/#{index}/alt_text", "an image needs alt_text unless decorative is true.")
        end
      end
    end
    private_class_method :media_problems

    def listing_url_problems(items, where, out)
      return unless items.is_a?(Array)

      items.each_with_index do |item, index|
        https_problem(item["public_url"], "#{where}/#{index}/public_url", "public_url", out) if item.is_a?(Hash)
      end
    end
    private_class_method :listing_url_problems

    def instant(value)
      Time.iso8601(value)
    rescue ArgumentError
      nil
    end
    private_class_method :instant

    def tax_problems(items, out)
      return unless items.is_a?(Array)

      seen = Set.new
      items.each_with_index do |item, index|
        next unless item.is_a?(Hash)

        if item["jurisdiction"].is_a?(String)
          msg = place_code_problem(item["jurisdiction"])
          out << problem("/tax_registrations/#{index}/jurisdiction", msg) if msg
        end
        id = [item["jurisdiction"], item["scheme"], item["number"]].map { |v| js_string(v) }.join("|")
        out << problem("/tax_registrations/#{index}", "tax registration jurisdiction, scheme and number are not unique.") if seen.include?(id)
        seen << id
        next unless item["verification_expires_at"].is_a?(String) && item["verified_at"].is_a?(String)

        expires = instant(item["verification_expires_at"])
        verified = instant(item["verified_at"])
        if expires.nil? || verified.nil? || expires <= verified
          out << problem("/tax_registrations/#{index}/verification_expires_at", "verification_expires_at must be later than verified_at.")
        end
      end
    end
    private_class_method :tax_problems

    def nested_country_code(value)
      return nil unless value.is_a?(Hash)

      value["code"].is_a?(String) ? value["code"] : nil
    end
    private_class_method :nested_country_code

    # The semantic checks of a schema-valid record. Returns [conformance, business_key] problem
    # lists: the first is schema_invalid, the second business_key_mismatch.
    def semantic_problems(record)
      conformance = []
      business_key = []
      if Host.identity_parts(record["identity_host"]).nil?
        conformance << problem("/identity_host", "identity_host is not a valid DNS host name with an optional path.")
      end
      Array(record["domains"]).each_with_index do |domain, i|
        conformance << problem("/domains/#{i}", "\"#{domain.to_s[0, 80]}\" is not a valid domain name.") unless Host.safe_host?(domain)
      end
      country_code = nested_country_code(record["country"])
      if country_code.nil?
        conformance << problem("/country", "country must be an object with code and name.")
      else
        msg = country_code_problem(country_code)
        conformance << problem("/country/code", msg) if msg
      end
      root_region = record["region"]
      if root_region.is_a?(Hash) && root_region["code"].is_a?(String) && country_code
        msg = BusinessKey.region_code_problem(root_region["code"], country_code)
        conformance << problem("/region/code", msg) if msg
      end
      %w[website logo_url mcp_server_url blog_url rss_url].each do |key|
        value = record[key]
        if value.is_a?(String) && !Host.safe_https_url?(value)
          conformance << problem("/#{key}", "#{key} must be an https URL with a public DNS host name.")
        end
      end
      %w[services links].each do |collection|
        items = record[collection]
        next unless items.is_a?(Array)

        items.each_with_index do |item, i|
          if item.is_a?(Hash) && item["url"].is_a?(String) && !Host.safe_https_url?(item["url"])
            conformance << problem("/#{collection}/#{i}/url", "url must be an https URL with a public DNS host name.")
          end
        end
      end
      forbidden_key_problems(record, "", conformance)
      social_problems(record["social_profiles"], "/social_profiles", conformance)
      category_problems(record["categories"], "/categories", conformance)
      media_problems(record["media"], conformance)
      locations = record["locations"]
      if locations.is_a?(Array)
        locations.each_with_index do |loc, i|
          next unless loc.is_a?(Hash)

          %w[street city postal_code].each do |key|
            conformance << problem("/locations/#{i}/#{key}", "#{key} is not a location member; use address.") if loc.key?(key)
          end
          addr = loc["address"].is_a?(Hash) ? loc["address"] : nil
          address_country = addr && addr["country"].is_a?(Hash) ? addr["country"]["code"] : nil
          if address_country.is_a?(String)
            msg = country_code_problem(address_country)
            conformance << problem("/locations/#{i}/address/country/code", msg) if msg
          end
          region = addr && addr["region"].is_a?(Hash) ? addr["region"] : nil
          if region && region["code"].is_a?(String) && address_country.is_a?(String)
            msg = BusinessKey.region_code_problem(region["code"], address_country)
            conformance << problem("/locations/#{i}/address/region/code", msg) if msg
          end
          geo = loc["geo"]
          if geo.is_a?(Hash)
            street = addr && addr["street_lines"].is_a?(Array) && !addr["street_lines"].empty?
            conformance << problem("/locations/#{i}/geo", "geo requires address.street_lines.") unless street
            lat = geo["latitude"]
            lon = geo["longitude"]
            if !lat.is_a?(Numeric) || lat < -90 || lat > 90 || !lon.is_a?(Numeric) || lon < -180 || lon > 180
              conformance << problem("/locations/#{i}/geo", "geo coordinates out of valid WGS 84 range.")
            end
          end
          https_problem(loc["website"], "/locations/#{i}/website", "website", conformance)
          social_problems(loc["social_profiles"], "/locations/#{i}/social_profiles", conformance)
          category_problems(loc["categories"], "/locations/#{i}/categories", conformance)
          listing_url_problems(loc["external_listings"], "/locations/#{i}/external_listings", conformance)
          hours = loc["opening_hours"]
          opening_hour_problems(hours, "/locations/#{i}/opening_hours", conformance) if hours.is_a?(Hash)
          listing_problems(loc, "/locations/#{i}", conformance)
          area_problems(loc["service_areas"], "/locations/#{i}/service_areas", conformance)
        end
        seen_ids = Set.new
        locations.each_with_index do |loc, index|
          next unless loc.is_a?(Hash) && loc["location_id"].is_a?(String)

          if seen_ids.include?(loc["location_id"])
            conformance << problem("/locations/#{index}/location_id", "location_id \"#{loc["location_id"]}\" is not unique.")
          end
          seen_ids << loc["location_id"]
        end
      end
      listing_problems(record, "", conformance)
      tax_problems(record["tax_registrations"], conformance)
      key = record["business_key"]
      if key.is_a?(String)
        parsed, message = BusinessKey.parse(key)
        if parsed.nil?
          business_key << problem("/business_key", message)
        else
          if country_code && parsed.country != country_code.downcase
            business_key << problem("/business_key", "business_key's country does not match country.")
          end
          if parsed.number != js_string(record["registration_number"]).upcase
            business_key << problem("/business_key", "business_key's registration number does not match registration_number.")
          end
        end
      end
      [conformance, business_key]
    end

    # The assertion against the record and the queried domain: [identity_host_matches,
    # queried_domain_in_record, business_key_problems].
    def link_checks(record, domain, assertion)
      identity = Host.identity_parts(record["identity_host"])
      identity_matches = !identity.nil? && identity == assertion.h
      declared = Set.new(Array(record["domains"]).map { |d| d.to_s.downcase.sub(/\.\z/, "") })
      domain_in_record = declared.include?(domain)
      problems = []
      key = record["business_key"]
      if !assertion.k.nil? && key.is_a?(String) && !BusinessKey.same?(assertion.k, key)
        problems << problem("/business_key", "The DNS k= tag and the record business_key differ.")
      elsif key.nil? && !assertion.k.nil?
        problems << problem("/business_key", "The DNS assertion has k= but the record has no business_key.")
      end
      [identity_matches, domain_in_record, problems]
    end
  end
end
