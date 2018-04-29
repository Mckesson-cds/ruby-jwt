# frozen_string_literal: true

require 'spec_helper'
require 'jwt/verify'

RSpec.describe JWT::Verify do
  let(:base_payload) { { 'user_id' => 'some@user.tld' } }

  context 'raise_errors is true' do
    let(:options) { { leeway: 0 } }

    context '.verify_aud(payload, options)' do
      let(:scalar_aud) { 'ruby-jwt-aud' }
      let(:array_aud) { %w[ruby-jwt-aud test-aud ruby-ruby-ruby] }
      let(:scalar_payload) { base_payload.merge('aud' => scalar_aud) }
      let(:array_payload) { base_payload.merge('aud' => array_aud) }

      it 'must raise JWT::InvalidAudError when the singular audience does not match' do
        expect do
          described_class.verify_aud(scalar_payload, options.merge(aud: 'no-match'))
        end.to raise_error JWT::InvalidAudError
      end

      it 'must raise JWT::InvalidAudError when the payload has an array and none match the supplied value' do
        expect do
          described_class.verify_aud(array_payload, options.merge(aud: 'no-match'))
        end.to raise_error JWT::InvalidAudError
      end

      it 'must allow a matching singular audience to pass' do
        described_class.verify_aud(scalar_payload, options.merge(aud: scalar_aud))
      end

      it 'must allow an array with any value matching the one in the options' do
        described_class.verify_aud(array_payload, options.merge(aud: array_aud.first))
      end

      it 'must allow an array with any value matching any value in the options array' do
        described_class.verify_aud(array_payload, options.merge(aud: array_aud))
      end

      it 'must allow a singular audience payload matching any value in the options array' do
        described_class.verify_aud(scalar_payload, options.merge(aud: array_aud))
      end
    end

    context '.verify_expiration(payload, options)' do
      let(:payload) { base_payload.merge('exp' => (Time.now.to_i - 5)) }

      it 'must raise JWT::ExpiredSignature when the token has expired' do
        expect do
          described_class.verify_expiration(payload, options)
        end.to raise_error JWT::ExpiredSignature
      end

      it 'must allow some leeway in the expiration when global leeway is configured' do
        described_class.verify_expiration(payload, options.merge(leeway: 10))
      end

      it 'must allow some leeway in the expiration when exp_leeway is configured' do
        described_class.verify_expiration(payload, options.merge(exp_leeway: 10))
      end

      it 'must be expired if the exp claim equals the current time' do
        payload['exp'] = Time.now.to_i

        expect do
          described_class.verify_expiration(payload, options)
        end.to raise_error JWT::ExpiredSignature
      end

      context 'when leeway is not specified' do
        let(:options) { {} }

        it 'used a default leeway of 0' do
          expect do
            described_class.verify_expiration(payload, options)
          end.to raise_error JWT::ExpiredSignature
        end
      end
    end

    context '.verify_iat(payload, options)' do
      let(:iat) { Time.now.to_f }
      let(:payload) { base_payload.merge('iat' => iat) }

      it 'must allow a valid iat' do
        described_class.verify_iat(payload, options)
      end

      it 'must ignore configured leeway' do
        expect{described_class.verify_iat(payload.merge('iat' => (iat + 60)), options.merge(leeway: 70)) }
          .to raise_error(JWT::InvalidIatError)
      end

      it 'must properly handle integer times' do
        described_class.verify_iat(payload.merge('iat' => Time.now.to_i), options)
      end

      it 'must raise JWT::InvalidIatError when the iat value is not Numeric' do
        expect do
          described_class.verify_iat(payload.merge('iat' => 'not a number'), options)
        end.to raise_error JWT::InvalidIatError
      end

      it 'must raise JWT::InvalidIatError when the iat value is in the future' do
        expect do
          described_class.verify_iat(payload.merge('iat' => (iat + 120)), options)
        end.to raise_error JWT::InvalidIatError
      end
    end

    context '.verify_iss(payload, options)' do
      let(:iss) { 'ruby-jwt-gem' }
      let(:payload) { base_payload.merge('iss' => iss) }

      let(:invalid_token) { JWT.encode base_payload, payload[:secret] }

      context 'when iss is a String' do
        it 'must raise JWT::InvalidIssuerError when the configured issuer does not match the payload issuer' do
          expect do
            described_class.verify_iss(payload, options.merge(iss: 'mismatched-issuer'))
          end.to raise_error JWT::InvalidIssuerError
        end

        it 'must raise JWT::InvalidIssuerError when the payload does not include an issuer' do
          expect do
            described_class.verify_iss(base_payload, options.merge(iss: iss))
          end.to raise_error(JWT::InvalidIssuerError, /received <none>/)
        end

        it 'must allow a matching issuer to pass' do
          described_class.verify_iss(payload, options.merge(iss: iss))
        end
      end
      context 'when iss is an Array' do
        it 'must raise JWT::InvalidIssuerError when no matching issuers in array' do
          expect do
            described_class.verify_iss(payload, options.merge(iss: %w[first second]))
          end.to raise_error JWT::InvalidIssuerError
        end

        it 'must raise JWT::InvalidIssuerError when the payload does not include an issuer' do
          expect do
            described_class.verify_iss(base_payload, options.merge(iss: %w[first second]))
          end.to raise_error(JWT::InvalidIssuerError, /received <none>/)
        end

        it 'must allow an array with matching issuer to pass' do
          described_class.verify_iss(payload, options.merge(iss: ['first', iss, 'third']))
        end
      end
    end

    context '.verify_jti(payload, options)' do
      let(:payload) { base_payload.merge('jti' => 'some-random-uuid-or-whatever') }

      it 'must allow any jti when the verfy_jti key in the options is truthy but not a proc' do
        described_class.verify_jti(payload, options.merge(verify_jti: true))
      end

      it 'must raise JWT::InvalidJtiError when the jti is missing' do
        expect do
          described_class.verify_jti(base_payload, options)
        end.to raise_error JWT::InvalidJtiError, /missing/i
      end

      it 'must raise JWT::InvalidJtiError when the jti is an empty string' do
        expect do
          described_class.verify_jti(base_payload.merge('jti' => '   '), options)
        end.to raise_error JWT::InvalidJtiError, /missing/i
      end

      it 'must raise JWT::InvalidJtiError when verify_jti proc returns false' do
        expect do
          described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti) { false }))
        end.to raise_error JWT::InvalidJtiError, /invalid/i
      end

      it 'true proc should not raise JWT::InvalidJtiError' do
        described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti) { true }))
      end

      it 'it should not throw arguement error with 2 args' do
        expect do
          described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti, pl) {
            true
          }))
        end.to_not raise_error
      end
      it 'should have payload as second param in proc' do
        described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti, pl) {
          expect(pl).to eq(payload)
        }))
      end
    end

    context '.verify_not_before(payload, options)' do
      let(:payload) { base_payload.merge('nbf' => (Time.now.to_i + 5)) }

      it 'must raise JWT::ImmatureSignature when the nbf in the payload is in the future' do
        expect do
          described_class.verify_not_before(payload, options)
        end.to raise_error JWT::ImmatureSignature
      end

      it 'must allow some leeway in the token age when global leeway is configured' do
        described_class.verify_not_before(payload, options.merge(leeway: 10))
      end

      it 'must allow some leeway in the token age when nbf_leeway is configured' do
        described_class.verify_not_before(payload, options.merge(nbf_leeway: 10))
      end
    end

    context '.verify_sub(payload, options)' do
      let(:sub) { 'ruby jwt subject' }

      it 'must raise JWT::InvalidSubError when the subjects do not match' do
        expect do
          described_class.verify_sub(base_payload.merge('sub' => 'not-a-match'), options.merge(sub: sub))
        end.to raise_error JWT::InvalidSubError
      end

      it 'must allow a matching sub' do
        described_class.verify_sub(base_payload.merge('sub' => sub), options.merge(sub: sub))
      end
    end
  end

  context 'raise_errors is false' do
    let(:options) { { leeway: 0, raise_errors: false } }

    context '.verify_aud(payload, options)' do
      let(:scalar_aud) { 'ruby-jwt-aud' }
      let(:array_aud) { %w[ruby-jwt-aud test-aud ruby-ruby-ruby] }
      let(:scalar_payload) { base_payload.merge('aud' => scalar_aud) }
      let(:array_payload) { base_payload.merge('aud' => array_aud) }

      it 'has an :aud error when the singular audience does not match' do
        verifier = described_class.verify_aud(scalar_payload, options.merge(aud: 'no-match'))
        expect(verifier).to be_invalid
        expect(verifier.errors[:aud]).to include(match /Invalid audience/)
      end

      it 'has an :aud error when the payload has an array and none match the supplied value' do
        verifier = described_class.verify_aud(array_payload, options.merge(aud: 'no-match'))
        expect(verifier).to be_invalid
        expect(verifier.errors[:aud]).to include(match /Invalid audience/)
      end

      it 'has no :aud error with a matching singular audience' do
        verifier = described_class.verify_aud(scalar_payload, options.merge(aud: scalar_aud))
        expect(verifier).to be_valid
      end

      it 'has no :aud error with an array with any value matching the one in the options' do
        verifier = described_class.verify_aud(array_payload, options.merge(aud: array_aud.first))
        expect(verifier).to be_valid
      end

      it 'has no :aud error with an array with any value matching any value in the options array' do
        verifier = described_class.verify_aud(array_payload, options.merge(aud: array_aud))
        expect(verifier).to be_valid
      end

      it 'has no :aud error with a singular audience payload matching any value in the options array' do
        verifier = described_class.verify_aud(scalar_payload, options.merge(aud: array_aud))
        expect(verifier).to be_valid
      end
    end

    context '.verify_expiration(payload, options)' do
      let(:payload) { base_payload.merge('exp' => (Time.now.to_i - 5)) }

      it 'has an :exp error when the token has expired' do
        verifier = described_class.verify_expiration(payload, options)
        expect(verifier).to be_invalid
        expect(verifier.errors[:exp]).to include(match /Signature has expired/)
      end

      it 'has no :exp error with some leeway in the expiration when global leeway is configured' do
        verifier = described_class.verify_expiration(payload, options.merge(leeway: 10))
        expect(verifier).to be_valid
      end

      it 'has no :exp error with some leeway in the expiration when exp_leeway is configured' do
        verifier = described_class.verify_expiration(payload, options.merge(exp_leeway: 10))
        expect(verifier).to be_valid
      end

      it 'has an :exp error when the exp claim equals the current time' do
        payload['exp'] = Time.now.to_i

        verifier = described_class.verify_expiration(payload, options)
        expect(verifier.errors[:exp]).to include(match /Signature has expired/)
      end

      context 'when leeway is not specified' do
        it 'uses a default leeway of 0' do
          verifier = described_class.verify_expiration(payload, options.except(:leeway))
          expect(verifier).to be_invalid
          expect(verifier.errors[:exp]).to include(match /Signature has expired/)
        end
      end
    end

    context '.verify_iat(payload, options)' do
      let(:iat) { Time.now.to_f }
      let(:payload) { base_payload.merge('iat' => iat) }

      it 'no :iat error with a valid iat' do
        verifier = described_class.verify_iat(payload, options)
        expect(verifier).to be_valid
      end

      it 'must ignore configured leeway' do
        verifier = described_class.verify_iat(payload.merge('iat' => (iat + 60)), options.merge(leeway: 70))
        expect(verifier).to be_invalid
        expect(verifier.errors[:iat]).to include(match /Invalid iat/)
      end

      it 'must properly handle integer times' do
        verifier = described_class.verify_iat(payload.merge('iat' => Time.now.to_i), options)
        expect(verifier).to be_valid
      end

      it 'has :iat error when the iat value is not Numeric' do
        verifier = described_class.verify_iat(payload.merge('iat' => 'not a number'), options)
        expect(verifier).to be_invalid
        expect(verifier.errors[:iat]).to include(match /Invalid iat/)
      end

      it 'has :iat error when the iat value is in the future' do
        verifier = described_class.verify_iat(payload.merge('iat' => (iat + 120)), options)
        expect(verifier).to be_invalid
        expect(verifier.errors[:iat]).to include(match /Invalid iat/)
      end
    end

    context '.verify_iss(payload, options)' do
      let(:iss) { 'ruby-jwt-gem' }
      let(:payload) { base_payload.merge('iss' => iss) }
      let(:invalid_token) { JWT.encode base_payload, payload[:secret] }

      context 'when iss is a String' do
        it 'has an :iss error when the configured issuer does not match the payload issuer' do
          verifier = described_class.verify_iss(payload, options.merge(iss: 'mismatched-issuer'))
          expect(verifier).to be_invalid
          expect(verifier.errors[:iss]).to include(match /Invalid issuer/)
        end

        it 'has an :iss error when the payload does not include an issuer' do
          verifier = described_class.verify_iss(base_payload, options.merge(iss: iss))
          expect(verifier).to be_invalid
          expect(verifier.errors[:iss]).to include(match /received <none>/)
        end

        it 'has no :iss error with a matching issuer' do
          verifier = described_class.verify_iss(payload, options.merge(iss: iss))
          expect(verifier).to be_valid
        end
      end

      context 'when iss is an Array' do
        it 'has an :iss error when no matching issuers in array' do
          verifier = described_class.verify_iss(payload, options.merge(iss: %w[first second]))
          expect(verifier).to be_invalid
          expect(verifier.errors[:iss]).to include(match /Invalid issuer/)
        end

        it 'has an :iss error when the payload does not include an issuer' do
          verifier = described_class.verify_iss(base_payload, options.merge(iss: %w[first second]))
          expect(verifier).to be_invalid
          expect(verifier.errors[:iss]).to include(match /received <none>/)
        end

        it 'has no :iss error with an array with matching issuer' do
          verifier = described_class.verify_iss(payload, options.merge(iss: ['first', iss, 'third']))
          expect(verifier).to be_valid
        end
      end
    end

    context '.verify_jti(payload, options)' do
      let(:payload) { base_payload.merge('jti' => 'some-random-uuid-or-whatever') }

      it 'has no :jti error when the verfy_jti key in the options is truthy but not a proc' do
        verifier = described_class.verify_jti(payload, options.merge(verify_jti: true))
        expect(verifier).to be_valid
      end

      it 'has a :jti error when the jti is missing' do
        verifier = described_class.verify_jti(base_payload, options.merge(verify_jti: true))
        expect(verifier).to be_invalid
        expect(verifier.errors[:jti]).to include(match /missing/i)
      end

      it 'has a :jti error when the jti is an empty string' do
        verifier = described_class.verify_jti(base_payload.merge('jti' => '   '), options.merge(verify_jti: true))
        expect(verifier).to be_invalid
        expect(verifier.errors[:jti]).to include(match /missing/i)
      end

      it 'has a :jti error when verify_jti proc returns false' do
        verifier = described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti) { false }))
        expect(verifier).to be_invalid
        expect(verifier.errors[:jti]).to include(match /invalid/i)
      end

      it 'has no :jti error with a true proc' do
        verifier = described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti) { true }))
        expect(verifier).to be_valid
      end

      it 'has no :jti error with 2 args' do
        verifier = described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti, _pl) { true }))
        expect(verifier).to be_valid
      end

      it 'should have payload as second param in proc' do
        described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti, pl) do
          expect(pl).to eq(payload)
        end))
      end
    end

    context '.verify_not_before(payload, options)' do
      let(:payload) { base_payload.merge('nbf' => (Time.now.to_i + 5)) }

      it 'has an :nbf error when the nbf in the payload is in the future' do
        verifier = described_class.verify_not_before(payload, options)
        expect(verifier).to be_invalid
        expect(verifier.errors[:nbf]).to include(match /nbf has not been reached/)
      end

      it 'must allow some leeway in the token age when global leeway is configured' do
        verifier = described_class.verify_not_before(payload, options.merge(leeway: 10))
        expect(verifier).to be_valid
      end

      it 'must allow some leeway in the token age when nbf_leeway is configured' do
        verifier = described_class.verify_not_before(payload, options.merge(nbf_leeway: 10))
        expect(verifier).to be_valid
      end
    end

    context '.verify_sub(payload, options)' do
      let(:sub) { 'ruby jwt subject' }

      it 'has a :sub error when the subjects do not match' do
        verifier = described_class.verify_sub(base_payload.merge('sub' => 'not-a-match'), options.merge(sub: sub))
        expect(verifier).to be_invalid
        expect(verifier.errors[:sub]).to include(match /Invalid subject/)
      end

      it 'has no :sub error with matching sub' do
        verifier = described_class.verify_sub(base_payload.merge('sub' => sub), options.merge(sub: sub))
        expect(verifier).to be_valid
      end
    end
  end
end
