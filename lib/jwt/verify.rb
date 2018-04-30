# frozen_string_literal: true

require 'jwt/error'
require 'jwt/claim_verifiable'

module JWT
  # JWT verify methods
  class Verify
    include ClaimVerifiable

    DEFAULTS = {
      leeway: 0,
      raise_errors: true
    }.freeze

    class << self
      %w[verify_aud verify_expiration verify_iat verify_iss verify_jti verify_not_before verify_sub].each do |method_name|
        define_method method_name do |payload, options|
          new(payload, options).tap { |verifier| verifier.send(method_name) }
        end
      end

      def verify_claims(payload, options)
        options.each do |key, val|
          next unless key.to_s =~ /verify/
          Verify.send(key, payload, options) if val
        end
      end
    end

    def initialize(payload, options)
      @payload = payload
      @options = DEFAULTS.merge(options)
      @raise_errors = @options[:raise_errors]
    end
  end
end
