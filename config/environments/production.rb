require "active_support/core_ext/integer/time"

Rails.application.configure do
  config.enable_reloading = false
  config.eager_load       = true
  config.consider_all_requests_local = false

  config.action_cable.url    = ENV.fetch("REDIS_URL", "redis://localhost:6379/0")
  config.action_cable.allowed_request_origins = [
    /http:\/\/localhost(:\d+)?/,
    /http:\/\/127\.0\.0\.1(:\d+)?/
  ]

  config.active_record.dump_schema_after_migration = false

  config.action_controller.perform_caching = true
  config.cache_store = :redis_cache_store, {
    url: ENV.fetch("REDIS_URL", "redis://localhost:6379/0"),
    reconnect_attempts: 3
  }

  config.log_level  = :info
  config.log_tags   = [:request_id]
  config.logger     = ActiveSupport::TaggedLogging.new(
    ActiveSupport::Logger.new(
      Rails.root.join("log/production.log"),
      10,
      50.megabytes
    )
  )
  config.assets.compile = false
  config.public_file_server.enabled = true
  config.public_file_server.headers = { "Cache-Control" => "public, max-age=#{1.year.to_i}" }

  config.force_ssl = false
  config.action_mailer.perform_caching    = false
  config.action_mailer.default_url_options = { host: "localhost", port: 3000 }
  config.i18n.fallbacks     = true
  config.active_support.report_deprecations = false
end