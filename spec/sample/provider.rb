module Rack
  module OAuth2
    #module Test
      class TestProvider < ::Sinatra::Base
        register ::Rack::OAuth2::Sinatra

        oauth.authenticator = lambda do |username,password|
          user = TestUser.find(username:username)
          user if user && user.authenticated?(password)
        end

      end
    #end
  end
end