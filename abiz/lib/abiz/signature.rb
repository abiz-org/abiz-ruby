# frozen_string_literal: true

require "openssl"
require_relative "jcs"

module Abiz
  # The outcome of a check that either passes or names one error code.
  Check = Struct.new(:code, :message, :path, keyword_init: true) do
    def ok?
      code.nil?
    end
  end

  # The record's own proof (SPEC section 4.6): public_key must equal the DNS p, and signature must
  # be a valid PureEd25519 signature by that key over the UTF-8 bytes of the RFC 8785 form of the
  # record with only its top-level signature member removed.
  module Signature
    SIGNATURE = %r{\A[A-Za-z0-9+/]{85}[AQgw]==\z}
    PUBLIC_KEY = %r{\A[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=\z}
    # DER prefixes: SubjectPublicKeyInfo and PKCS #8 for an Ed25519 key (RFC 8410).
    SPKI_PREFIX = ["302a300506032b6570032100"].pack("H*").freeze
    PKCS8_PREFIX = ["302e020100300506032b657004220420"].pack("H*").freeze

    module_function

    # The bytes the signature signs: JCS of the record without its top-level signature, as UTF-8.
    # Raises JCS::Error for a value that is not I-JSON.
    def signing_input(record)
      rest = record.reject { |key, _| key == "signature" }
      JCS.canonicalize(rest).b
    end

    # Check a record (a Hash) against the DNS p value. Returns Check: ok, or public_key_mismatch,
    # or signature_invalid.
    def verify(record, p)
      unless record.is_a?(Hash)
        return Check.new(code: "public_key_mismatch", path: "/public_key", message: "The record is not a JSON object.")
      end

      public_key = record["public_key"]
      signature = record["signature"]
      if !public_key.is_a?(String) || !public_key.match?(PUBLIC_KEY) || public_key != p
        message = p ? "public_key must equal the DNS p= value exactly." : "The DNS assertion has no p= key, so the record public_key is not vouched for."
        return Check.new(code: "public_key_mismatch", path: "/public_key", message: message)
      end
      unless signature.is_a?(String) && signature.match?(SIGNATURE)
        return Check.new(code: "signature_invalid", path: "/signature", message: "signature must be 64 bytes of Ed25519 signature in standard base64.")
      end

      begin
        data = signing_input(record)
      rescue JCS::Error => e
        return Check.new(code: "signature_invalid", path: "$", message: "The record cannot be canonicalised (RFC 8785): #{e.message}.")
      end
      valid = begin
        key = public_key_from_raw(public_key.unpack1("m0"))
        key.verify(nil, signature.unpack1("m0"), data)
      rescue OpenSSL::PKey::PKeyError, ArgumentError
        false
      end
      return Check.new if valid

      Check.new(code: "signature_invalid", path: "/signature",
                message: "signature does not verify with public_key over the RFC 8785 form of the record without signature.")
    end

    # An OpenSSL Ed25519 public key from its 32 raw bytes.
    def public_key_from_raw(raw)
      raise ArgumentError, "an Ed25519 public key is 32 bytes" unless raw.bytesize == 32

      OpenSSL::PKey.read(SPKI_PREFIX + raw)
    end

    # An OpenSSL Ed25519 private key from a 32-byte seed, or the key itself.
    def private_key(key)
      return key if key.is_a?(OpenSSL::PKey::PKey)
      raise ArgumentError, "an Ed25519 private key is a 32-byte seed or an OpenSSL::PKey" unless key.is_a?(String) && key.bytesize == 32

      OpenSSL::PKey.read(PKCS8_PREFIX + key.b)
    end

    # The standard base64 public key of an Ed25519 private key.
    def public_key_base64(pkey)
      der = pkey.public_to_der
      raise ArgumentError, "not an Ed25519 key" unless der.bytesize == 44 && der.byteslice(0, 12) == SPKI_PREFIX

      [der.byteslice(12, 32)].pack("m0")
    end

    # A producer helper: a copy of +record+ with public_key set to the key's public half and
    # signature set over the result. +private_key+ is a 32-byte seed or an OpenSSL Ed25519 key.
    def sign(record, private_key)
      raise ArgumentError, "the record must be a Hash" unless record.is_a?(Hash)

      pkey = self.private_key(private_key)
      out = record.reject { |key, _| key == "signature" }
      out["public_key"] = public_key_base64(pkey)
      sig = pkey.sign(nil, signing_input(out))
      out["signature"] = [sig].pack("m0")
      out
    end
  end
end
