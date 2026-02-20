require "redis"
require "connection_pool"

REDIS_URL  = ENV.fetch("REDIS_URL",  "redis://localhost:6379/0")
POOL_SIZE  = ENV.fetch("REDIS_POOL", "10").to_i
POOL_TIMEOUT = 3

$redis_pool = ConnectionPool.new(size: POOL_SIZE, timeout: POOL_TIMEOUT) do
  Redis.new(
    url: REDIS_URL, 
    reconnect_attempts: 3,
  )
end

Rails.logger.info "[Redis] Connection pool initialized — #{POOL_SIZE} connections → #{REDIS_URL}"