module ApplicationCable
  class Channel < ActionCable::Channel::Base
    after_subscribe  :log_subscription
    after_unsubscribe :log_unsubscription

    private

    def log_subscription
      logger.info "[ActionCable] #{self.class.name} subscribed — " \
                  "connection=#{connection.connection_identifier}"
    end

    def log_unsubscription
      logger.info "[ActionCable] #{self.class.name} unsubscribed — " \
                  "connection=#{connection.connection_identifier}"
    end
  end
end
