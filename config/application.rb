require_relative "boot"
require "rails/all"
require 'dotenv/rails-now'
require_relative '../app/lib/middleware/ip_request_limit'

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)
Dotenv::Railtie.load

module RazonetPocJwt
  class Application < Rails::Application
    # Initialize configuration defaults for originally generated Rails version.
    config.load_defaults 7.0

    # Configuration for the application, engines, and railties goes here.
    #
    # These settings can be overridden in specific environments using the files
    # in config/environments, which are processed later.
    #
    # config.time_zone = "Central Time (US & Canada)"
    # config.eager_load_paths << Rails.root.join("extras")

    # Only loads a smaller set of middleware suitable for API only apps.
    # Middleware like session, flash, cookies can be added back manually.
    # Skip views, helpers and assets when generating a new resource.
    config.api_only = true
    config.autoload_paths << Rails.root.join('app', 'lib')
    config.cache_store = :redis_cache_store, { url: ENV['REDIS_URL'] }
    config.middleware.use IpRequestLimit, routes: ['/api/auth/login', '/api/auth/register', '/api/auth/generate_pin', '/api/auth/login_pin', '/api/auth/users']
  end
end
