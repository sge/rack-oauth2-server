module Rack
  module OAuth2
    #module Test
      class TestConsumer < ::Sinatra::Base
       
       get '/' do
        'Hello World'
       end

      end
    #end
  end
end