module Rack
  module OAuth2
    class Server

      # Access token. This is what clients use to access resources.
      #
      # An access token is a unique code, associated with a client, an identity
      # and scope. It may be revoked, or expire after a certain period.
      class AccessToken
        include ::Mongoid::Document
        include ::Mongoid::Timestamps
        include ::Mongoid::UUID

        field :identity, type: String           # The identity we authorized access to.
        field :client_uuid, type: String        # Client that was granted this access token.
        field :scope, type: Array, default: []               # The scope granted to this token.
        field :expires_at, type: DateTime       # When token expires for good.
        field :revoked_at, type: DateTime       # Timestamp if revoked.
        field :last_accessed_at, type: DateTime # Timestamp of last access using this token, rounded up to hour.
        field :prev_accessed_at, type: DateTime # Timestamp of previous access using this token, rounded up to hour.

        def token; uuid; end

        index client_uuid: 1
        index identity: 1

        class << self

          # Find AccessToken from token. Does not return revoked tokens.
          def from_token(token)
            where( uuid: token, revoked_at: nil ).first
          end

          # Get an access token (create new one if necessary).
          #
          # You can set optional expiration in seconds. If zero or nil, token
          # never expires.
          def get_token_for(identity, client, scope, expires = nil)
            raise ArgumentError, "Identity must be String or Integer (got: #{identity.inspect})" unless String === identity || Integer === identity
            scope = Utils.normalize_scope(scope) & Utils.normalize_scope(client.scope) # Only allowed scope

            token = where( identity: identity, scope: scope, client_uuid: client.uuid, revoked_at: nil ).any_of({:'expires_at.gte' => Time.now }, { expires_at: nil }).first

            return token ? token : create_token_for(client,scope,identity,expires)
          end

          # Creates a new AccessToken for the given client and scope.
          def create_token_for(client, scope, identity = nil, expires = nil)
            expires_at = Time.now + expires if expires && expires != 0

            token = self.create({ scope: scope, client_uuid: client.uuid, expires_at: expires_at, identity: identity })

            if token
              client.inc({ tokens_granted: 1 })
              return token
            else
              raise "unable to create access token"
            end
          end

          # Find all AccessTokens for an identity.
          def from_identity(identity)
            where(identity:identity)
          end

          # Returns all access tokens for a given client, Use limit and offset
          # to return a subset of tokens, sorted by creation date.
          def for_client(client_uuid, offset = 0, limit = 100)
            where( client_uuid: client_uuid ).sort(created_at:1).skip(offset).limit(limit)
          end

          # Returns count of access tokens.
          #
          # @param [Hash] filter Count only a subset of access tokens
          # @option filter [Integer] days Only count that many days (since now)
          # @option filter [Boolean] revoked Only count revoked (true) or non-revoked (false) tokens; count all tokens if nil
          # @option filter [String, ObjectId] client_id Only tokens grant to this client
          def count(filter = {})
            select = {}
            if filter[:days]
              now = Time.now.to_i
              range = { :$gt=>now - filter[:days] * 86400, :$lte=>now }
              select[ filter[:revoked] ? :revoked : :created_at ] = range
            elsif filter.has_key?(:revoked)
              select[:revoked] = filter[:revoked] ? { :$ne=>nil } : { :$eq=>nil }
            end
            select[:client_id] = filter[:client_id] if filter[:client_id]
            collection.find(select).count
          end

          def historical(filter = {})
            days = filter[:days] || 60
            select = { :$gt=> { :created_at=>Time.now - 86400 * days } }
            select = {}
            if filter[:client_id]
              select[:client_id] = filter[:client_id]
            end
            raw = Server::AccessToken.collection.group("function (token) { return { ts: Math.floor(token.created_at / 86400) } }",
              select, { :granted=>0 }, "function (token, state) { state.granted++ }")
            raw.sort { |a, b| a["ts"] - b["ts"] }
          end

          # def collection
          #   prefix = Server.options[:collection_prefix]
          #   Server.database["#{prefix}.access_tokens"]
          # end
        end

        def identity
          attributes['identity']
        end

        # Updates the last access timestamp.
        def access!
          self.last_accessed_at = Time.now
          self.save
        end

        # Revokes this access token.
        def revoke!
          self.revoked_at = Time.now
          self.save
          client = Client.where(uuid:client_uuid).inc :tokens_revoked, 1
        end

      end

    end
  end
end
