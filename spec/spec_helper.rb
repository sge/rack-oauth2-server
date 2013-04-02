require 'rubygems'
require 'bundler'

Bundler.require

Mongoid.load!("./spec/sample/mongoid.yml", :test)

require 'rack-oauth2-server'
require "rack/oauth2/sinatra"
require 'sinatra/base'

require './spec/sample/user'
require './spec/sample/provider'
require './spec/sample/consumer'

require 'rspec'
require 'rack/test'

RSpec.configure do |conf|
  conf.include Rack::Test::Methods
end

module Sinatra
  class Base
    set :show_exceptions, false
  end
end

module Rack
  module OAuth2
    module Test
      class Combined < ::Sinatra::Base
        set :environment, :test
        use Rack::OAuth2::TestConsumer
        use Rack::OAuth2::TestProvider
      end
    end
  end
end