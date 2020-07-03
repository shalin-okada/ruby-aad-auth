require "aad_auth/version"
require "net/http"
require "json"
require "jwt"

module AadAuth
  class Aad
    def auth!(token)
      keys = self.get_jwk_set()
      jwk_loader = ->(options) do
        @cached_keys = nil if options[:invalidate]
        @cached_keys ||= keys
      end

      claims = JWT.decode(token, nil, true, { algorithm: 'RS256', jwks: jwk_loader })
      self.validate_exp(claims[0]["exp"])
      self.validate_aud(claims[0]["aud"])
    end

    private
    def get_jwk_set()
      keysUri = "https://login.microsoftonline.com/#{ENV["TENANT_ID"]}/discovery/v2.0/keys?appid=#{ENV["APP_ID"]}"
      response = Net::HTTP.get_response(URI.parse(keysUri))
      if response.code != 200
        raise UnauthorizedError.new("Fail to get JWK Set from Microsoft.")
      else
        keys = JSON.parse(response.body, symbolize_names: true)
      end
    end

    def validate_exp(exp)
      raise UnauthorizedError.new("The token has expired.") unless exp > Time.now.to_i
    end

    def validate_aud(aud)
      raise UnauthorizedError.new("AppID dosen't match with the token aud.") unless aud === ENV["APP_ID"]
    end
  end

  class UnauthorizedError < StandardError
    def initialize(msg="Unauthorized")
      super
    end
  end

end