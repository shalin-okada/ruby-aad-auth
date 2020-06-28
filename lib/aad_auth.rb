require "aad_auth/version"
require "net/http"
require "json"
require "jwt"

module AadAuth
  def self.auth(tenantId, appId, token)
    keysUri = "https://login.microsoftonline.com/#{tenantId}/discovery/v2.0/keys?appid=#{appId}"
    response = Net::HTTP.get_response(URI.parse(keysUri))
    keys = JSON.parse(response.body, symbolize_names: true)

    jwk_loader = ->(options) do
      @cached_keys = nil if options[:invalidate]
      @cached_keys ||= keys
    end

    begin
      claims = JWT.decode(token, nil, true, { algorithm: 'RS256', jwks: jwk_loader })
      timestamp = Time.now.to_i

      unless claims[0]["exp"] > timestamp
        return UnauthorizedException.new("The token has expired.")
      end
      
      unless claims[0]["aud"] === appId
        raise UnauthorizedException.new("AppID dosen't match with the token aud.")
      end
    rescue => e
      return JSON.generate({"success":false, "message":e.message})
    end
    return JSON.generate({"success":true, "message":"Succecc to auth."})
  end
end
