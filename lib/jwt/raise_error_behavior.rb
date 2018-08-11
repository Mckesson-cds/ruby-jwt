# frozen_string_literal: true

module JWT
  module RaiseErrorBehavior
    def handle_error(_attribute, error_class, error_message)
      raise error_class, error_message
    end
  end
end
