# frozen_string_literal: true

require 'spec_helper'
require 'jwt'
require 'jwt/decode'
require 'jwt/signature_verifiable'

RSpec.describe JWT::SignatureVerifiable do
  describe 'validates algorithm' do
    class TestAlgVerifier
      include JWT::SignatureVerifiable

      attr_reader :signing_input, :signature, :key

      def initialize(alg: 'HS256', key: 'subtract-skillet-paid-lots', iss: 'http://foo', algorithms: nil, raise_errors: true)
        @key = key
        @header = { 'alg' => alg }
        @payload = { 'iss' => iss, 'user_id' => 'foo@example.com' }
        @options = { algorithms: algorithms }
        @raise_errors = raise_errors
        encoder = JWT::Encode.new(payload, key, alg, {})
        @signing_input = [encoder.encoded_header, encoder.encoded_payload].join('.')
        @signature = JWT::Signature.sign(alg, @signing_input, key)
      end
    end

    context 'raise_errors is true' do
      context 'with matching single algorithm' do
        it 'does not raise an error' do
          verifier = TestAlgVerifier.new(alg: 'HS256', algorithms: 'HS256')
          expect { verifier.validate }.to_not raise_error
        end
      end

      context 'with matching algorithm array' do
        it 'does not raise an error' do
          verifier = TestAlgVerifier.new(alg: 'HS256', algorithms: %w[HS512 HS256])
          expect { verifier.validate }.to_not raise_error
        end
      end

      context 'with no matching algorithm' do
        it 'raises an error' do
          verifier = TestAlgVerifier.new(alg: 'HS256', algorithms: %w[RS512])
          expect { verifier.validate }.to raise_error JWT::IncorrectAlgorithm
        end
      end

      context 'with no algorithms' do
        it 'raises an error' do
          verifier1 = TestAlgVerifier.new(algorithms: nil)
          expect { verifier1.validate }.to raise_error JWT::IncorrectAlgorithm

          verifier2 = TestAlgVerifier.new(algorithms: [])
          expect { verifier2.validate }.to raise_error JWT::IncorrectAlgorithm
        end
      end
    end

    context 'raise_errors is false' do
      context 'with matching single algorithm' do
        it 'has no errors' do
          verifier = TestAlgVerifier.new(raise_errors: false, alg: 'HS256', algorithms: 'HS256')
          expect(verifier).to be_valid
        end
      end

      context 'with matching algorithm array' do
        it 'has no errors' do
          verifier = TestAlgVerifier.new(raise_errors: false, alg: 'HS256', algorithms: %w[HS512 HS256])
          expect(verifier).to be_valid
        end
      end

      context 'with no matching algorithm' do
        it 'has an :alg error' do
          verifier = TestAlgVerifier.new(raise_errors: false, alg: 'HS256', algorithms: %w[RS512])
          expect(verifier).to be_invalid
          expect(verifier.errors[:alg]).to include(match /invalid alg/i)
        end
      end

      context 'with no algorithms' do
        it 'has a :base error' do
          verifier1 = TestAlgVerifier.new(raise_errors: false, algorithms: nil)
          expect(verifier1).to be_invalid
          expect(verifier1.errors[:base]).to include(match /algorithm must be specified/)

          verifier2 = TestAlgVerifier.new(raise_errors: false, algorithms: [])
          expect(verifier2).to be_invalid
          expect(verifier2.errors[:base]).to include(match /algorithm must be specified/)
        end
      end
    end
  end

  describe 'validates signature' do
    class TestSigVerifier
      include JWT::SignatureVerifiable

      attr_reader :signing_input, :signature, :key

      def initialize(jwt, key = nil, _verify = true, options = {}, &keyfinder)
        @jwt = jwt
        @options = { raise_errors: true }.merge(options)
        @raise_errors = @options[:raise_errors]
        decoder = JWT::Decode.new(jwt, true)
        @header, @payload, @signature, @signing_input = decoder.decode_segments
        @key = (keyfinder.arity == 2 ? yield(@header, @payload) : yield(@header)) if keyfinder
        @key ||= key
      end
    end

    let(:data) do
      {
        :secret => 'My$ecretK3y',
        :rsa_private => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'rsa-2048-private.pem'))),
        :rsa_public => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'rsa-2048-public.pem'))),
        :wrong_rsa_private => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'rsa-2048-wrong-public.pem'))),
        :wrong_rsa_public => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'rsa-2048-wrong-public.pem'))),
        'ES256_private' => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec256-private.pem'))),
        'ES256_public' => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec256-public.pem'))),
        'ES384_private' => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec384-private.pem'))),
        'ES384_public' => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec384-public.pem'))),
        'ES512_private' => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec512-private.pem'))),
        'ES512_public' => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec512-public.pem'))),
        'ED25519_private' => RbNaCl::Signatures::Ed25519::SigningKey.new('abcdefghijklmnopqrstuvwxyzABCDEF'),
        'ED25519_public' => RbNaCl::Signatures::Ed25519::SigningKey.new('abcdefghijklmnopqrstuvwxyzABCDEF').verify_key,
        'NONE' => 'eyJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.',
        'HS256' => 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.kWOVtIOpWcG7JnyJG0qOkTDbOy636XrrQhMm_8JrRQ8',
        'HS512256' => 'eyJhbGciOiJIUzUxMjI1NiJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.Ds_4ibvf7z4QOBoKntEjDfthy3WJ-3rKMspTEcHE2bA',
        'HS384' => 'eyJhbGciOiJIUzM4NCJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.VuV4j4A1HKhWxCNzEcwc9qVF3frrEu-BRLzvYPkbWO0LENRGy5dOiBQ34remM3XH',
        'HS512' => 'eyJhbGciOiJIUzUxMiJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.8zNtCBTJIZTHpZ-BkhR-6sZY1K85Nm5YCKqV3AxRdsBJDt_RR-REH2db4T3Y0uQwNknhrCnZGvhNHrvhDwV1kA',
        'RS256' => 'eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.eSXvWP4GViiwUALj_-qTxU68I1oM0XjgDsCZBBUri2Ghh9d75QkVDoZ_v872GaqunN5A5xcnBK0-cOq-CR6OwibgJWfOt69GNzw5RrOfQ2mz3QI3NYEq080nF69h8BeqkiaXhI24Q51joEgfa9aj5Y-oitLAmtDPYTm7vTcdGufd6AwD3_3jajKBwkh0LPSeMtbe_5EyS94nFoEF9OQuhJYjUmp7agsBVa8FFEjVw5jEgVqkvERSj5hSY4nEiCAomdVxIKBfykyi0d12cgjhI7mBFwWkPku8XIPGZ7N8vpiSLdM68BnUqIK5qR7NAhtvT7iyLFgOqhZNUQ6Ret5VpQ',
        'RS384' => 'eyJhbGciOiJSUzM4NCJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.Sfgk56moPghtsjaP4so6tOy3I553mgwX-5gByMC6dX8lpeWgsxSeAd_K8IyO7u4lwYOL0DSftnqO1HEOuN1AKyBbDvaTXz3u2xNA2x4NYLdW4AZA6ritbYcKLO5BHTXw5ueMbtA1jjGXP0zI_aK2iJTMBmB8SCF88RYBUH01Tyf4PlLj98pGL-v3prZd6kZkIeRJ3326h04hslcB5HQKmgeBk24QNLIoIC-CD329HPjJ7TtGx01lj-ehTBnwVbBGzYFAyoalV5KgvL_MDOfWPr1OYHnR5s_Fm6_3Vg4u6lBljvHOrmv4Nfx7d8HLgbo8CwH4qn1wm6VQCtuDd-uhRg',
        'RS512' => 'eyJhbGciOiJSUzUxMiJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.LIIAUEuCkGNdpYguOO5LoW4rZ7ED2POJrB0pmEAAchyTdIK4HKh1jcLxc6KyGwZv40njCgub3y72q6vcQTn7oD0zWFCVQRIDW1911Ii2hRNHuigiPUnrnZh1OQ6z65VZRU6GKs8omoBGU9vrClBU0ODqYE16KxYmE_0n4Xw2h3D_L1LF0IAOtDWKBRDa3QHwZRM9sHsHNsBuD5ye9KzDYN1YALXj64LBfA-DoCKfpVAm9NkRPOyzjR2X2C3TomOSJgqWIVHJucudKDDAZyEbO4RA5pI-UFYy1370p9bRajvtDyoBuLDCzoSkMyQ4L2DnLhx5CbWcnD7Cd3GUmnjjTA',
        'ES256' => '',
        'ES384' => '',
        'ES512' => ''
      }
    end

    after(:each) do
      expect(OpenSSL.errors).to be_empty
    end

    let(:payload) { { 'user_id' => 'foo@example.com' } }

    context 'raise_errors is true' do
      %w[HS256 HS512256 HS384 HS512].each do |alg|
        context "with alg #{alg}" do
          context 'with a valid signature' do
            it 'does not raise an error' do
              verifier = TestSigVerifier.new(data[alg], data[:secret], true, algorithm: alg)
              expect(verifier).to be_valid
            end
          end

          context 'with an invalid signature' do
            it 'raises an error' do
              verifier = TestSigVerifier.new(data[alg], 'wrong-secret', true, algorithm: alg)
              expect { verifier.validate }.to raise_error JWT::VerificationError
            end
          end
        end
      end

      %w[RS256 RS384 RS512].each do |alg|
        context "with alg #{alg}" do
          context 'with a valid signature' do
            it 'does not raise an error' do
              verifier = TestSigVerifier.new(data[alg], data[:rsa_public], true, algorithm: alg)
              expect(verifier).to be_valid
            end
          end

          context 'with an invalid signature' do
            it 'raises an error' do
              key = OpenSSL::PKey.read File.read(File.join(CERT_PATH, 'rsa-2048-wrong-public.pem'))
              verifier = TestSigVerifier.new(data[alg], key, true, algorithm: alg)
              expect { verifier.validate }.to raise_error JWT::VerificationError
            end
          end
        end
      end

      context 'with alg ED25519' do
        let(:token) { JWT.encode(payload, data['ED25519_private'], 'ED25519') }

        let(:wrong_key) { OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec256-wrong-public.pem'))) }

        context 'with a valid signature' do
          it 'does not raise an error' do
            verifier = TestSigVerifier.new(token, data['ED25519_public'], true, algorithm: 'ED25519')
            expect(verifier).to be_valid
          end
        end

        context 'with an invalid signature' do
          it 'raises an error' do
            verifier = TestSigVerifier.new(token, wrong_key, false, algorithm: 'ED25519')
            expect { verifier.validate }.to raise_error JWT::VerificationError
          end
        end
      end
    end

    context 'raise_errors is false' do
      %w[HS256 HS512256 HS384 HS512].each do |alg|
        context "with alg #{alg}" do
          context 'with a valid signature' do
            it 'has no errors' do
              verifier = TestSigVerifier.new(data[alg], data[:secret], true, algorithm: alg, raise_errors: false)
              expect(verifier).to be_valid
            end
          end

          context 'with an invalid signature' do
            it 'has a :base error' do
              verifier = TestSigVerifier.new(data[alg], 'wrong-secret', true, algorithm: alg, raise_errors: false)
              expect(verifier).to be_invalid
              expect(verifier.errors[:base]).to include(match /signature invalid/i)
            end
          end
        end
      end

      %w[RS256 RS384 RS512].each do |alg|
        context "with alg #{alg}" do
          context 'with a valid signature' do
            it 'has no errors' do
              verifier = TestSigVerifier.new(data[alg], data[:rsa_public], true, algorithm: alg, raise_errors: false)
              expect(verifier).to be_valid
            end
          end

          context 'with an invalid signature' do
            it 'has a :base error' do
              key = OpenSSL::PKey.read File.read(File.join(CERT_PATH, 'rsa-2048-wrong-public.pem'))
              verifier = TestSigVerifier.new(data[alg], key, true, algorithm: alg, raise_errors: false)
              expect(verifier).to be_invalid
              expect(verifier.errors[:base]).to include(match /signature invalid/i)
            end
          end
        end
      end
    end
  end
end
