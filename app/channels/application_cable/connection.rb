module ApplicationCable
  class Connection < ActionCable::Connection::Base
    identified_by :connection_identifier

    def connect
      self.connection_identifier = verify_cookie!
      logger.info "[ActionCable] New connection: #{connection_identifier}"
    end

    def disconnect
      logger.info "[ActionCable] Disconnected: #{connection_identifier}"
    end

    private

    def verify_cookie!
      cable_token  = ENV.fetch("CABLE_TOKEN", nil)
      return "anonymous" if cable_token.nil?

      provided = cookies.signed[:cable_token].to_s
      if ActiveSupport::SecurityUtils.secure_compare(provided, cable_token)
        "authenticated-#{SecureRandom.hex(4)}"
      else
        logger.warn "[ActionCable] Rejected unauthorized connection from #{request.remote_ip}"
        reject_unauthorized_connection
      end
    end
  end
end