# frozen_string_literal: true

puts "In #{__FILE__}"

module JWT
  USE_ACTIVEMODEL_VALIDATIONS = true
end

require 'jwt'
require 'active_model'

module JWT
  class Verify
    include ActiveModel::Validations # unless klass.ancestors.include? ActiveModel::Validations
    validate :verify_aud
    validate :verify_expiration
    validate :verify_iat
    validate :verify_iss
    validate :optionally_verify_jti
    validate :verify_not_before
    validate :verify_sub

    private

    def handle_error(attribute, _klass, message)
      errors.add(attribute, message)
    end
  end
end
