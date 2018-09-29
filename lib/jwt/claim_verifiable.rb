# frozen_string_literal: true

require 'active_model'

module JWT
  module ClaimVerifiable
    attr_reader :payload, :options, :raise_errors

    def self.included(klass)
      klass.include ActiveModel::Validations unless klass.ancestors.include? ActiveModel::Validations
      klass.validate :verify_aud
      klass.validate :verify_expiration
      klass.validate :verify_iat
      klass.validate :verify_iss
      klass.validate :optionally_verify_jti
      klass.validate :verify_not_before
      klass.validate :verify_sub
    end

    def verify_aud
      return unless (options_aud = @options[:aud])
      aud = @payload['aud']
      handle_error(:aud, JWT::InvalidAudError, "Invalid audience. Expected #{options_aud}, received #{aud || '<none>'}") if ([*aud] & [*options_aud]).empty?
    end

    def verify_expiration
      return unless @payload.include?('exp')
      handle_error(:exp, JWT::ExpiredSignature, 'Signature has expired') if @payload['exp'].to_i <= (Time.now.to_i - exp_leeway)
    end

    def verify_iat
      return unless @payload.include?('iat')
      iat = @payload['iat']
      handle_error(:iat, JWT::InvalidIatError, "Invalid iat (iat: #{iat.to_f}, now: #{Time.now.to_f})") if !iat.is_a?(Numeric) || iat.to_f > Time.now.to_f
    end

    def verify_iss
      return unless (options_iss = @options[:iss])
      iss = @payload['iss']
      return if Array(options_iss).map(&:to_s).include?(iss.to_s)
      handle_error(:iss, JWT::InvalidIssuerError, "Invalid issuer. Expected #{options_iss}, received #{iss || '<none>'}")
    end

    def optionally_verify_jti
      verify_jti if @options[:verify_jti]
    end

    def verify_jti
      options_verify_jti = @options[:verify_jti]
      jti = @payload['jti']

      if options_verify_jti.respond_to?(:call)
        verified = options_verify_jti.arity == 2 ? options_verify_jti.call(jti, @payload) : options_verify_jti.call(jti)
        handle_error(:jti, JWT::InvalidJtiError, 'Invalid jti') unless verified
      elsif jti.to_s.strip.empty?
        handle_error(:jti, JWT::InvalidJtiError, 'Missing jti')
      end
    end

    def verify_not_before
      return unless @payload.include?('nbf')
      handle_error(:nbf, JWT::ImmatureSignature, 'Signature nbf has not been reached') if @payload['nbf'].to_i > (Time.now.to_i + nbf_leeway)
    end

    def verify_sub
      return unless (options_sub = @options[:sub])
      sub = @payload['sub']
      handle_error(:sub, JWT::InvalidSubError, "Invalid subject. Expected #{options_sub}, received #{sub || '<none>'}") unless sub.to_s == options_sub.to_s
    end

    private

    def handle_error(attribute, klass, message)
      if @raise_errors
        raise klass, message
      else
        errors.add(attribute, message)
      end
    end

    def global_leeway
      @options[:leeway]
    end

    def exp_leeway
      @options[:exp_leeway] || global_leeway
    end

    def iat_leeway
      @options[:iat_leeway] || global_leeway
    end

    def nbf_leeway
      @options[:nbf_leeway] || global_leeway
    end
  end
end
