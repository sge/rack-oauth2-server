require 'spec_helper'

describe Rack::OAuth2::Test::Combined do
  include Rack::Test::Methods
  def app; subject; end

  def random_string
    SecureRandom.uuid.downcase.gsub('-','').first(8)
  end

  before do
    @user = TestUser.find_or_create_by username: 'bob'
    @user.update_attribute :password, random_string

    @client = Rack::OAuth2::Server::Client.where(display_name:'Samplr2').first
    unless @client
      @client = Rack::OAuth2::Server::Client.create({
        display_name: 'Samplr2',
        scope: [],
        secret: random_string,
        redirect_uri: 'http://www.redirect.com/'
      })
    end
  end

  it "says hello" do
    get '/'
    last_response.should be_ok
    last_response.body.should == 'Hello World'
  end

  it 'allows you to login' do
    get '/oauth/authorize', { redirect_uri: 'http://www.redirect.com/', client_id: @client.uuid, client_secret: @client.secret, response_type: 'code' }

    require 'pp'
    puts "~~~~~~~~~~~~~~~~~~~>>>"
    puts last_response.errors
    pp last_response.inspect
    puts "~~~~~~~~~~~~~~~~~~~>>>"

    last_response.should be_ok
  end


end