require_relative "../lib/middleware/ingester"
require_relative "boot"
require "rails/all"

Bundler.require(*Rails.groups)

module AnomalyPlatform
  class Application < Rails::Application
    config.load_defaults 7.1
    config.middleware.insert_before 0, AnomalyIngester
    config.action_cable.cable = {
      "adapter" => "redis",
      "url"     => ENV.fetch("REDIS_URL", "redis://localhost:6379/0")
    }

    config.time_zone              = "UTC"
    config.eager_load_paths      << Rails.root.join("lib")
    config.api_only               = false
  end
end