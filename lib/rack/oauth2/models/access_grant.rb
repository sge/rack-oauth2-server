module Rack
  module OAuth2
    class Server

      # The access grant is a nonce, new grant created each time we need it and
      # good for redeeming one access token.
      class AccessGrant
        include ::Mongoid::Document
        include ::Mongoid::Timestamps
        include ::Mongoid::UUID

        field :identity, type: String     # The identity we authorized access to.
        field :client_uuid, type: String  # Client that was granted this access token.
        field :redirect_uri, type: String # Redirect URI for this grant.
        field :scope, type: Array, default: []         # The scope requested in this grant.
        field :granted_at, type: DateTime # Tells us when (and if) access token was created.
        field :expires_at, type: DateTime # Tells us when this grant expires.
        field :access_token, type: String # Access token created from this grant. Set and spent.
        field :revoked_at, type: DateTime # Timestamp if revoked.

        index client_uuid: 1

        # alias :code :uuid
        def code; uuid; end

        class << self
          # Find AccessGrant from authentication code.
          def from_code(code)
            self.where(uuid:code).first
          end
        end

        def client
          Client.where(uuid: self.client_uuid).first
        end

        def identity
          attributes['identity']
        end

        # Authorize access and return new access token.
        #
        # Access grant can only be redeemed once, but client can make multiple
        # requests to obtain it, so we need to make sure only first request is
        # successful in returning access token, futher requests raise
        # InvalidGrantError.
        #
        def authorize!(expires_in = nil)
          raise InvalidGrantError, "You can't use the same access grant twice" if self.access_token || self.revoked_at.present?
          raise InvalidGrantError unless client.present?

          access_token = AccessToken.get_token_for(identity, client, scope, expires_in)

          self.access_token = access_token.token
          self.granted_at   = Time.now
          self.save!

          return access_token
        end

        def revoke!
          update_attribute :revoked_at, Time.now
        end

      end

    end
  end
end
