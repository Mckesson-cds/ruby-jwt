# frozen_string_literal: true

require 'spec_helper'
require 'jwt/activemodel'

RSpec.describe JWT::Verify do
  let(:base_payload) { { 'user_id' => 'some@user.tld' } }

  let(:options) { { leeway: 0 } }

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
