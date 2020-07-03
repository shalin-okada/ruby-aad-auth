require "aad_auth"

RSpec.describe AadAuth do
    let(:instance) { AadAuth::Aad.new() }
    context 'ENV["APP_ID"] is null.' do
        before do
            ENV["APP_ID"] = nil
        end
        it 'get_jwk_set raise error' do
            expect { instance.send(:get_jwk_set) }.to raise_error(AadAuth::UnauthorizedError)
        end
    end
    context 'ENV["TENANT_ID"] is null.' do
        before do
            ENV["APP_TENANT"] = nil
        end
        it 'get_jwk_set raise error' do
            expect { instance.send(:get_jwk_set) }.to raise_error(AadAuth::UnauthorizedError)
        end
    end

    context 'token is old.' do
        let(:exp) { 1591955413 }
        it 'validate_exp raise error' do
            expect { instance.send(:validate_exp, exp) }.to raise_error(AadAuth::UnauthorizedError)
        end
    end

    context 'aud is incorect.' do
        let(:aud) { "00000003-0000-0000-c000-000000000000" }
        it 'validate_aud raise error' do
            expect { instance.send(:validate_aud, aud) }.to raise_error(AadAuth::UnauthorizedError)
        end
    end
end
