# frozen_string_literal: true

require 'active_model'
require 'jwt/algos/hmac'
require 'jwt/algos/ecdsa'
require 'jwt/algos/eddsa'
require 'jwt/algos/rsa'
require 'jwt/algos/unsupported'
require 'jwt/error'
require 'jwt/security_utils'

module JWT
  module SignatureVerifiable
    ALGOS = [
      Algos::Hmac,
      Algos::Ecdsa,
      Algos::Rsa,
      Algos::Eddsa,
      Algos::Unsupported
    ].freeze

    attr_reader :header, :payload, :options, :raise_errors

    def self.included(klass)
      klass.include ActiveModel::Validations unless klass.ancestors.include? ActiveModel::Validations
      klass.validate :verify_algorithm
      klass.validate :verify_signature
    end

    private

    def allowed_algorithms
      @allowed_algorithms ||= begin
        if options.key?(:algorithm)
          [options[:algorithm]].compact
        else
          options[:algorithms] || []
        end
      end
    end

    def verify_algorithm
      if allowed_algorithms.empty?
        handle_error(:base, JWT::IncorrectAlgorithm, 'An algorithm must be specified')
      elsif !allowed_algorithms.include?(header['alg'])
        handle_error(:alg, JWT::IncorrectAlgorithm, "Invalid alg: #{header['alg'].inspect}")
      end
    end

    def verify_signature
      algo = ALGOS.find { |alg| alg.const_get(:SUPPORTED).include? header['alg'] }
      verified = algo.verify(ToVerify.new(header['alg'], key, signing_input, signature))
      handle_error(:base, JWT::VerificationError, 'Signature invalid') unless verified
    rescue OpenSSL::PKey::PKeyError
      handle_error(:base, JWT::VerificationError, 'Signature invalid')
    ensure
      OpenSSL.errors.clear
    end

    def handle_error(attribute, klass, message)
      if @raise_errors
        raise klass, message
      elsif attribute == :base
        errors[:base] << message
      else
        errors.add(attribute, message)
      end
    end
  end
end
