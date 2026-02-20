require "active_support/core_ext/integer/time"

Rails.application.configure do
  config.enable_reloading = true
  config.eager_load = false
  config.consider_all_requests_local = true
  config.server_timing = true
  config.action_cable.url = ENV.fetch("REDIS_URL", "redis://localhost:6379/0")
  config.action_cable.disable_request_forgery_protection = true

  config.active_record.migration_error       = :page_load
  config.active_record.verbose_query_logs    = true
  config.active_record.query_log_tags_enabled = true

  if Rails.root.join("tmp/caching-dev.txt").exist?
    config.action_controller.perform_caching = true
    config.cache_store = :memory_store
  else
    config.action_controller.perform_caching = false
    config.cache_store = :null_store
  end

  config.log_level        = :debug
  config.log_tags         = [:request_id]
  config.logger           = ActiveSupport::TaggedLogging.new(ActiveSupport::Logger.new($stdout))
  config.active_record.logger = nil 
  
  config.action_mailer.raise_delivery_errors = false
  config.action_mailer.default_url_options   = { host: "localhost", port: 3000 }
  config.i18n.raise_on_missing_translations = true

  config.action_view.annotate_rendered_view_with_filenames = true
  config.action_controller.raise_on_missing_callback_actions = true
end
