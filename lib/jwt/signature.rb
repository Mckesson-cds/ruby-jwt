# frozen_string_literal: true

require 'jwt/security_utils'
require 'openssl'
require 'jwt/algos/hmac'
require 'jwt/algos/eddsa'
require 'jwt/algos/ecdsa'
require 'jwt/algos/rsa'
require 'jwt/algos/unsupported'
require 'jwt/raise_error_behavior'

begin
  require 'rbnacl'
rescue LoadError
  raise if defined?(RbNaCl)
end

# JWT::Signature module
module JWT
  # Signature logic for JWT
  module Signature
    include RaiseErrorBehavior

    extend self

    ALGOS = [
      Algos::Hmac,
      Algos::Ecdsa,
      Algos::Rsa,
      Algos::Eddsa,
      Algos::Unsupported
    ].freeze

    ToSign = Struct.new(:algorithm, :msg, :key)
    ToVerify = Struct.new(:algorithm, :public_key, :signing_input, :signature)

    def sign(algorithm, msg, key)
      algo = ALGOS.find do |alg|
        alg.const_get(:SUPPORTED).include? algorithm
      end
      algo.sign ToSign.new(algorithm, msg, key)
    end

    def verify(algorithm, key, signing_input, signature)
      algo = ALGOS.find do |alg|
        alg.const_get(:SUPPORTED).include? algorithm
      end
      verified = algo.verify(ToVerify.new(algorithm, key, signing_input, signature))
      handle_error(:base, JWT::VerificationError, 'Signature verification raised') unless verified
    rescue OpenSSL::PKey::PKeyError
      handle_error(:base, JWT::VerificationError, 'Signature verification raised')
    ensure
      OpenSSL.errors.clear
    end
  end
end
