# frozen_string_literal: true

require 'jwt/raise_error_behavior'

module JWT
  module Algos
    module Unsupported
      include RaiseErrorBehavior

      module_function

      SUPPORTED = Object.new.tap { |object| object.define_singleton_method(:include?) { |*| true } }
      def verify(*)
        handle_error(:alg, JWT::VerificationError, 'Algorithm not supported')
      end

      def sign(*)
        raise NotImplementedError, 'Unsupported signing method'
      end
    end
  end
end
