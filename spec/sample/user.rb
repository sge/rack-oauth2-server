class TestUser
  include ::Mongoid::Document
  field :username, type: String
  field :password, type: String
  field :name, type: String
end