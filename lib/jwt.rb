# frozen_string_literal: true

require 'base64'
require 'jwt/decode'
require 'jwt/default_options'
require 'jwt/encode'
require 'jwt/error'
require 'jwt/signature'
require 'jwt/signature_verifiable'
require 'jwt/verify'

# JSON Web Token implementation
#
# Should be up to date with the latest spec:
# https://tools.ietf.org/html/rfc7519
module JWT
  include JWT::DefaultOptions

  module_function

  def encode(payload, key, algorithm = 'HS256', header_fields = {})
    encoder = Encode.new payload, key, algorithm, header_fields
    encoder.segments
  end

  def decode(jwt, key = nil, verify = true, options = {}, &keyfinder)
    decoder = Decode.new(jwt, key, verify, DEFAULT_OPTIONS.merge(options), &keyfinder)
    decoder.decode_segments
  end
end
