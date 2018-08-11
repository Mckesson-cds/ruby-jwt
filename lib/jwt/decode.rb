# frozen_string_literal: true

require 'json'

require 'jwt/signature'
require 'jwt/verify'
require 'jwt/raise_error_behavior'

module JWT
  # Decoding logic for JWT
  class Decode
    include RaiseErrorBehavior

    def self.base64url_decode(str)
      str += '=' * (4 - str.length.modulo(4))
      Base64.decode64(str.tr('-_', '+/'))
    end

    def initialize(jwt, key, verify, options, &keyfinder)
      raise(JWT::DecodeError, 'Nil JSON web token') unless jwt
      @jwt = jwt
      @key = key
      @options = options
      @segments = jwt.split('.')
      @verify = verify
      @signature = ''
      @keyfinder = keyfinder
    end

    def decode_segments
      validate_segment_count
      if @verify
        decode_crypto
        verify_signature
        verify_claims
      end
      handle_error(:base, JWT::DecodeError, 'Not enough or too many segments') unless header && payload
      [payload, header]
    end

    private

    def verify_signature
      @key = find_key(&@keyfinder) if @keyfinder

      handle_error(:alg, JWT::IncorrectAlgorithm, 'An algorithm must be specified') if allowed_algorithms.empty?
      handle_error(:alg, JWT::IncorrectAlgorithm, 'Expected a different algorithm') unless options_includes_algo_in_header?

      Signature.verify(header['alg'], @key, signing_input, @signature)
    end

    def options_includes_algo_in_header?
      allowed_algorithms.include? header['alg']
    end

    def allowed_algorithms
      if @options.key?(:algorithm)
        [@options[:algorithm]]
      else
        @options[:algorithms] || []
      end
    end

    def find_key(&keyfinder)
      key = (keyfinder.arity == 2 ? yield(header, payload) : yield(header))
      handle_error(:base, JWT::DecodeError, 'No verification key available') unless key
      key
    end

    def verify_claims
      Verify.verify_claims(payload, @options)
    end

    def validate_segment_count
      handle_error(:base, JWT::DecodeError, 'Not enough or too many segments') unless
        (@verify && segment_length != 3) ||
            (segment_length != 3 || segment_length != 2)
    end

    def segment_length
      @segments.count
    end

    def decode_crypto
      @signature = Decode.base64url_decode(@segments[2])
    end

    def header
      @header ||= parse_and_decode @segments[0]
    end

    def payload
      @payload ||= parse_and_decode @segments[1]
    end

    def signing_input
      @segments.first(2).join('.')
    end

    def parse_and_decode(segment)
      JSON.parse(Decode.base64url_decode(segment))
    rescue JSON::ParserError
      handle_error(:base, JWT::DecodeError, 'Invalid segment encoding')
    end
  end
end
