# frozen_string_literal: true

module JWT
  ToSign = Struct.new(:algorithm, :msg, :key)
  ToVerify = Struct.new(:algorithm, :public_key, :signing_input, :signature)
end
