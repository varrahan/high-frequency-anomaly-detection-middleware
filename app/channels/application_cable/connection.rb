module ApplicationCable
  class Connection < ActionCable::Connection::Base
    identified_by :connection_identifier

    def connect
      self.connection_identifier = verify_token!
      logger.info "[ActionCable] New connection: #{connection_identifier}"
    end

    def disconnect
      logger.info "[ActionCable] Disconnected: #{connection_identifier}"
    end

    private

    # Authenticate the WebSocket connection via a bearer token passed as a
    # query parameter: ws://localhost:3000/cable?token=<CABLE_TOKEN>
    #
    # If CABLE_TOKEN is not set in the environment, all connections are
    # permitted — safe for local development, should be set in production.
    def verify_token!
      cable_token = ENV.fetch("CABLE_TOKEN", nil)
      return "anonymous" if cable_token.nil?

      provided = request.params[:token].to_s
      if ActiveSupport::SecurityUtils.secure_compare(provided, cable_token)
        "authenticated-#{SecureRandom.hex(4)}"
      else
        logger.warn "[ActionCable] Rejected unauthorized connection from #{request.remote_ip}"
        reject_unauthorized_connection
      end
    end
  end
end