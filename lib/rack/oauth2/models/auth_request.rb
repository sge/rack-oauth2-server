module Rack
  module OAuth2
    class Server

      # Authorization request. Represents request on behalf of client to access
      # particular scope. Use this to keep state from incoming authorization
      # request to grant/deny redirect.
      class AuthRequest
        class << self

          # Find AuthRequest from identifier.
          def find(request_id)
            where({ uuid: request_id }).first
          end

          # Create a new authorization request. This holds state, so in addition
          # to client ID and scope, we need to know the URL to redirect back to
          # and any state value to pass back in that redirect.
          def create(client, scope, redirect_uri, response_type, state)
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            super( client_uuid: client.uuid, scope: scope, redirect_uri: client.redirect_uri || redirect_uri, response_type: response_type, state: state )
          end

        end

        include ::Mongoid::Document
        include ::Mongoid::Timestamps
        include ::Mongoid::UUID

        field :identifier, type: String
        field :client_uuid, type: String      # client making the request
        field :scope, type: Array, default: []             # scope of the request (array of names)
        field :redirect_uri, type: String     # Redirect back to this URL.
        field :state, type: String            # client requested we return state on redirect
        field :responst_type, type: String    # either code or token
        field :grant_code, type: String       # if granted, the access grant code
        field :access_token, type: String     # if granted, the access token

        field :authorized_at, type: DateTime  # keeping track of things
        field :revoked_at, type: DateTime     # keeping track of things

        # Grant access to the specified identity.
        def grant!(identity, expires_in = nil)
          raise ArgumentError, "Must supply a identity" unless identity
          return if revoked_at.present?
          client = Client.where(uuid:client_uuid).first or return
          self.authorized_at = Time.now
          if response_type == "code" # Requested authorization code
            access_grant = AccessGrant.create({
              identity: identity, 
              client_uuid: client.uuid, 
              scope: scope, 
              redirect_uri: redirect_uri
            })
            self.grant_code = access_grant.code
            self.save
          else # Requested access token
            access_token = AccessToken.get_token_for(identity, client, scope, expires_in)
            self.access_token = access_token.token
            self.save
          end
          true
        end

        # Deny access.
        def deny!
          self.authorized_at = Time.now
          self.save
        end

      end
    end
  end
end
