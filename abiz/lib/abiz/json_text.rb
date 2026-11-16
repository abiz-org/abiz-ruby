# frozen_string_literal: true

module Abiz
  # Strict JSON reading for ABIZ records (I-JSON, RFC 7493), written here rather than taken from
  # JSON.parse because JSON.parse keeps the last of two repeated member names silently, so the
  # signed bytes and what a reader sees could differ (SPEC section 4.6), and because some versions
  # accept comments, which RFC 8259 does not.
  #
  # Values: objects become Hash (string keys, in document order), arrays Array, strings String
  # (UTF-8), true/false/nil, integer literals Integer and any literal with a fraction or exponent
  # Float. Canonicalisation (Abiz::JCS) treats every number as an IEEE 754 double, as ECMAScript does.
  module JsonText
    # Nesting and member limits a record must keep (the reference resolver's MAX_RECORD_DEPTH and
    # MAX_RECORD_KEYS).
    MAX_DEPTH = 16
    MAX_KEYS = 5_000

    # Raised for text that is not RFC 8259 JSON, or holds a lone surrogate (not I-JSON).
    class ParseError < StandardError; end

    # Raised for an object with a repeated member name. +pointer+ is the JSON Pointer of the
    # repeated member.
    class DuplicateMember < ParseError
      attr_reader :pointer

      def initialize(pointer)
        @pointer = pointer
        super("repeated member name at #{pointer.empty? ? "/" : pointer}")
      end
    end

    module_function

    # The first limit the text breaks, as the reference's scanJson does before parsing:
    # +:too_deep+, +:too_many_keys+ or nil. Counts every "{" and "[" outside strings for depth,
    # and every ":" outside strings as a member. Runs on any text, valid JSON or not.
    def shape_problem(text, max_depth: MAX_DEPTH, max_keys: MAX_KEYS)
      depth = 0
      deepest = 0
      keys = 0
      in_string = false
      bytes = text.b
      i = 0
      n = bytes.bytesize
      while i < n
        ch = bytes.getbyte(i)
        if in_string
          if ch == 0x5c
            i += 1
          elsif ch == 0x22
            in_string = false
          end
        elsif ch == 0x22
          in_string = true
        elsif ch == 0x7b || ch == 0x5b
          depth += 1
          deepest = depth if depth > deepest
          break if deepest > max_depth
        elsif ch == 0x7d || ch == 0x5d
          depth -= 1
        elsif ch == 0x3a
          keys += 1
          break if keys > max_keys
        end
        i += 1
      end
      return :too_deep if deepest > max_depth
      return :too_many_keys if keys > max_keys

      nil
    end

    # Parse +text+ as one JSON value. Raises ParseError (or DuplicateMember).
    def parse(text)
      Parser.new(text).parse
    end

    # :nodoc:
    class Parser
      WS = [0x20, 0x09, 0x0a, 0x0d].freeze
      MAX_NESTING = 512

      def initialize(text)
        str = text.to_s
        str = str.dup.force_encoding(Encoding::UTF_8) unless str.encoding == Encoding::UTF_8
        raise ParseError, "the text is not valid UTF-8" unless str.valid_encoding?

        @s = str
        @b = str.b
        @i = 0
        @n = @b.bytesize
        @nesting = 0
      end

      def parse
        skip_ws
        value = parse_value("")
        skip_ws
        raise ParseError, "unexpected text after the JSON value" if @i < @n

        value
      end

      private

      def peek
        @i < @n ? @b.getbyte(@i) : nil
      end

      def skip_ws
        @i += 1 while @i < @n && WS.include?(@b.getbyte(@i))
      end

      def expect(byte)
        raise ParseError, "expected #{byte.chr} at offset #{@i}" unless peek == byte

        @i += 1
      end

      def parse_value(path)
        case peek
        when 0x7b then parse_object(path)
        when 0x5b then parse_array(path)
        when 0x22 then parse_string
        when 0x74 then literal("true", true)
        when 0x66 then literal("false", false)
        when 0x6e then literal("null", nil)
        when 0x2d, 0x30..0x39 then parse_number
        else raise ParseError, "unexpected character at offset #{@i}"
        end
      end

      def literal(word, value)
        raise ParseError, "invalid literal at offset #{@i}" unless @b.byteslice(@i, word.bytesize) == word

        @i += word.bytesize
        value
      end

      def enter
        @nesting += 1
        raise ParseError, "nesting too deep" if @nesting > MAX_NESTING
      end

      def parse_object(path)
        enter
        @i += 1
        obj = {}
        skip_ws
        if peek == 0x7d
          @i += 1
          @nesting -= 1
          return obj
        end
        loop do
          skip_ws
          raise ParseError, "expected a member name at offset #{@i}" unless peek == 0x22

          key = parse_string
          member_path = "#{path}/#{key.gsub("~", "~0").gsub("/", "~1")}"
          raise DuplicateMember, member_path if obj.key?(key)

          skip_ws
          expect(0x3a)
          skip_ws
          obj[key] = parse_value(member_path)
          skip_ws
          case peek
          when 0x2c then @i += 1
          when 0x7d
            @i += 1
            break
          else raise ParseError, "expected , or } at offset #{@i}"
          end
        end
        @nesting -= 1
        obj
      end

      def parse_array(path)
        enter
        @i += 1
        arr = []
        skip_ws
        if peek == 0x5d
          @i += 1
          @nesting -= 1
          return arr
        end
        loop do
          skip_ws
          arr << parse_value("#{path}/#{arr.length}")
          skip_ws
          case peek
          when 0x2c then @i += 1
          when 0x5d
            @i += 1
            break
          else raise ParseError, "expected , or ] at offset #{@i}"
          end
        end
        @nesting -= 1
        arr
      end

      NUMBER = /\G-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/n

      def parse_number
        m = NUMBER.match(@b, @i)
        raise ParseError, "invalid number at offset #{@i}" unless m && m.begin(0) == @i

        text = m[0]
        @i += text.bytesize
        if m[1].nil? && m[2].nil?
          Integer(text, 10)
        else
          to_double(text)
        end
      end

      # The nearest double, as ECMAScript reads it: out of range gives +-Infinity or 0, without
      # Ruby's "out of range" warning.
      def to_double(text)
        verbose = $VERBOSE
        $VERBOSE = nil
        Float(text)
      ensure
        $VERBOSE = verbose
      end

      def parse_string
        @i += 1
        out = +""
        start = @i
        loop do
          raise ParseError, "unterminated string" if @i >= @n

          c = @b.getbyte(@i)
          if c == 0x22
            out << @b.byteslice(start, @i - start)
            @i += 1
            break
          elsif c == 0x5c
            out << @b.byteslice(start, @i - start)
            @i += 1
            out << escape
            start = @i
          elsif c < 0x20
            raise ParseError, "control character in a string at offset #{@i}"
          else
            @i += 1
          end
        end
        out.force_encoding(Encoding::UTF_8)
        raise ParseError, "a string is not valid UTF-8" unless out.valid_encoding?

        out
      end

      SIMPLE = { 0x22 => "\"", 0x5c => "\\", 0x2f => "/", 0x62 => "\b", 0x66 => "\f", 0x6e => "\n", 0x72 => "\r", 0x74 => "\t" }.freeze

      def escape
        c = peek
        raise ParseError, "unterminated escape" if c.nil?

        if SIMPLE.key?(c)
          @i += 1
          return SIMPLE[c].b
        end
        raise ParseError, "invalid escape at offset #{@i}" unless c == 0x75

        @i += 1
        unit = hex4
        if unit.between?(0xd800, 0xdbff)
          unless @b.byteslice(@i, 2) == "\\u"
            raise ParseError, "lone surrogate (not I-JSON)"
          end

          @i += 2
          low = hex4
          raise ParseError, "lone surrogate (not I-JSON)" unless low.between?(0xdc00, 0xdfff)

          code = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00)
          [code].pack("U").b
        elsif unit.between?(0xdc00, 0xdfff)
          raise ParseError, "lone surrogate (not I-JSON)"
        else
          [unit].pack("U").b
        end
      end

      def hex4
        h = @b.byteslice(@i, 4)
        raise ParseError, "invalid \\u escape at offset #{@i}" unless h && h.match?(/\A[0-9A-Fa-f]{4}\z/n)

        @i += 4
        h.to_i(16)
      end
    end
  end
end
