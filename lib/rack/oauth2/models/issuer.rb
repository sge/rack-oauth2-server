module Rack
  module OAuth2
    class Server

      # A third party that issues assertions
      # http://tools.ietf.org/html/draft-ietf-oauth-assertions-01#section-5.1
      class Issuer
        include ::Mongoid::Document
        include ::Mongoid::Timestamps
        include ::Mongoid::UUID

        field :identifier, type: String
        field :hmac_secret, type: String # shared secret used for verifying HMAC signatures
        field :public_key, type: String # public key used for verifying RSA signatures
        field :notes, type: String # notes about this Issuer

        index identifier: 1

        class << self

          # returns the Issuer object for the given identifier
          def from_identifier(identifier)
            where( identifier: identifier ).first
          end

          # Create a new Issuer.
          def create(args)
            super args.slice( :hmac_secret, :public_key, :notes, :identifier )
          end

        end

      end
    end
  end
end
