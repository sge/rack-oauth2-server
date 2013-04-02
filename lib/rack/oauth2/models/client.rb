require 'mongoid'

module Rack
  module OAuth2
    class Server
      class Client
        include ::Mongoid::Document
        include ::Mongoid::Timestamps
        include ::Mongoid::UUID

        field :secret, type: String
        field :display_name, type: String
        field :link, type: String
        field :image_url, type: String
        field :redirect_uri, type: String
        field :scope, type: Array, default: []
        field :notes, type: String
        field :revoked_at, type: DateTime
        field :tokens_granted, type: Integer, default: 0
        field :tokens_revoked, type: Integer, default: 0

        def id; uuid; end

        class << self

          # Authenticate a client request. This method takes three arguments,
          # Find Client from client identifier.
          def find(client_uuid)
            where(uuid:client_uuid).first
          end

          # Create a new client. Client provides the following properties:
          # # :display_name -- Name to show (e.g. UberClient)
          # # :link -- Link to client Web site (e.g. http://uberclient.dot)
          # # :image_url -- URL of image to show alongside display name
          # # :redirect_uri -- Registered redirect URI.
          # # :scope -- List of names the client is allowed to request.
          # # :notes -- Free form text.
          # 
          # This method does not validate any of these fields, in fact, you're
          # not required to set them, use them, or use them as suggested. Using
          # them as suggested would result in better user experience.  Don't ask
          # how we learned that.
          def create(fields)
            redirect_uri = Server::Utils.parse_redirect_uri(fields[:redirect_uri]).to_s if fields[:redirect_uri]
            scope        = Server::Utils.normalize_scope(fields[:scope])
            super({ scope: scope, redirect_uri: redirect_uri, secret: SecureRandom.uuid.downcase }.merge(fields))
          end

          # Lookup client by ID, display name or URL.
          def lookup(field)
            id = BSON::ObjectId(field.to_s)
            Server.new_instance self, collection.find_one(id)
          rescue BSON::InvalidObjectId
            Server.new_instance self, collection.find_one({ :display_name=>field }) || collection.find_one({ :link=>field })
          end

          # Deletes client with given identifier (also, all related records).
          def delete(client_uuid)
            client = self.where(uuid:client_uuid).first
            AuthRequest.where(client_uuid:client.uuid).destroy
            AccessGrant.where(client_uuid:client.uuid).destroy
            AccessToken.where(client_uuid:client.uuid).destroy
            client.destroy
          end

        end

        # Revoke all authorization requests, access grants and access tokens for
        # this client. Ward off the evil.
        def revoke!
          self.update_attribute :revoked_at, Time.now.to_i
          AuthRequest.where(client_uuid:uuid).update_attribute :revoked_at, Time.now
          AccessGrant.where(client_uuid:uuid).update_attribute :revoked_at, Time.now
          AccessToken.where(client_uuid:uuid).update_attribute :revoked_at, Time.now
        end

        # def update(args)
        #   fields = [:display_name, :link, :image_url, :notes].inject({}) { |h,k| v = args[k]; h[k] = v if v; h }
        #   fields[:redirect_uri] = Server::Utils.parse_redirect_uri(args[:redirect_uri]).to_s if args[:redirect_uri]
        #   fields[:scope] = Server::Utils.normalize_scope(args[:scope])
        #   self.class.collection.update({ :_id=>id }, { :$set=>fields })
        #   self.class.find(id)
        # end

        # Server.create_indexes do
        #   # For quickly returning clients sorted by display name, or finding
        #   # client from a URL.
        #   collection.create_index [[:display_name, Mongo::ASCENDING]]
        #   collection.create_index [[:link, Mongo::ASCENDING]]
        # end
      end

    end
  end
end
