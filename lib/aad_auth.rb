require "aad_auth/version"
require "net/http"
require "json"
require "jwt"

module AadAuth
  class Aad
    def self.auth(token)
      keys = get_jwt_keys
      jwk_loader = ->(options) do
        @cached_keys = nil if options[:invalidate]
        @cached_keys ||= keys
      end

      begin
        claims = JWT.decode(token, nil, true, { algorithm: 'RS256', jwks: jwk_loader })

        validate_exp(claims[0]["exp"])

        validate_aud(claims[0]["aud"])

      rescue => e
        return JSON.generate({"success":false, "message":e.message})
      end
      
      return JSON.generate({"success":true, "message":"Succeed to auth."})
    end

    private

    def get_jwt_keys
      keysUri = "https://login.microsoftonline.com/#{ENV["TENANT_ID"]}/discovery/v2.0/keys?appid=#{ENV["APP_ID"]}"
      response = Net::HTTP.get_response(URI.parse(keysUri))
      keys = JSON.parse(response.body, symbolize_names: true)
      return keys
    end
    
    def validate_exp(exp)
      raise UnauthorizedException.new("The token has expired.") unless exp > Time.now.to_i
    end

    def validate_aud(aud)
      raise UnauthorizedException.new("AppID dosen't match with the token aud.") unless aud === ENV["APP_ID"]
    end

  end
end
